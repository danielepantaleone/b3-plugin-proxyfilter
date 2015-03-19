#
# ProxyFilter Plugin for BigBrotherBot(B3) (www.bigbrotherbot.net)
# Copyright (C) 2014 Daniele Pantaleone <fenix@bigbrotherbot.net>
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
#
# CHANGELOG
#
# 2014/05/12 - 1.0   - Fenix - initial release
# 2014/05/13 - 1.0.1 - Fenix - minor fixes to debug messages
# 2014/05/14 - 1.0.2 - Fenix - added a new proxy detection service based on the Location Plugin
# 2015/02/01 - 1.1   - Fenix - use the new plugin structure
#                            - make plugin up to date with LocationPlugin changes
#                            - remove compatibility with B3 1.9.x
#                            - do not let the plugin crash B3 upon object construction
#                            - postgresql support
# 2015/02/23 - 1.2   - Fenix - changed plugin to use EVT_CLIENT_AUTH to correctly match client level
# 2015/03/19 - 1.3   - Fenix - changed plugin to use the new GeolocationPlugin

__author__ = 'Fenix'
__version__ = '1.3'

import b3
import b3.plugin
import b3.events
import os
import re

from b3.functions import getCmd
from ConfigParser import NoOptionError
from ConfigParser import NoSectionError
from proxyscanner import WinmxunlimitedProxyScanner
from proxyscanner import GeolocationPluginProxyScanner
from threading import Thread
from time import time


class ProxyfilterPlugin(b3.plugin.Plugin):

    adminPlugin = None

    settings = {
        'maxlevel': 40,
        'reason': '^1proxy detected',
        'timeout': 4,
        'services': {
            'winmxunlimited': {
                'enabled': True,
                'class': WinmxunlimitedProxyScanner,
                'url': 'http://winmxunlimited.net/api/proxydetection/v1/query/?ip=%s'
            },
            'geolocationplugin': {
                'enabled': True,
                'class': GeolocationPluginProxyScanner,
                'url': None
            }
        }
    }

    sql = {
        'q1': """INSERT INTO proxies (client_id, service, ip, time_add) VALUES ('%s', '%s', '%s', '%d')""",
        'q2': """SELECT COUNT(DISTINCT ip) AS total FROM proxies""",
        'q3': """SELECT service, COUNT(*) AS total FROM proxies GROUP BY service ORDER BY service ASC""",
    }

    services = {}

    ####################################################################################################################
    #                                                                                                                  #
    #   STARTUP                                                                                                        #
    #                                                                                                                  #
    ####################################################################################################################

    def __init__(self, console, config=None):
        """
        Build the plugin object.
        :param console: The console instance
        :param config: The plugin configuration file instance
        """
        b3.plugin.Plugin.__init__(self, console, config)

        self.adminPlugin = self.console.getPlugin('admin')
        if not self.adminPlugin:
            raise AttributeError('could not start without admin plugin')

        self._default_messages = {
            'client_rejected': '''^7$client has been ^1rejected^7: proxy detected''',
            'proxy_list': '''^7Proxy services: $services''',
            'stats_no_proxies': '''^7No proxy have been detected till now''',
            'stats_count_proxies': '''^^7[^4$count^7] ^7proxy detected till now''',
            'stats_detail_pattern': '''^7[^4$count^7] ^7: ^3$service'''
        }

    def onLoadConfig(self):
        """
        Load plugin configuration.
        """
        try:
            self.settings['maxlevel'] = self.console.getGroupLevel(self.config.get('settings', 'maxlevel'))
            self.debug('loaded settings/maxlevel: %s' % self.settings['maxlevel'])
        except NoOptionError:
            self.warning('could not find settings/maxlevel in config file, using default: %s' % self.settings['maxlevel'])
        except KeyError, e:
            self.error('could not load settings/maxlevel config value: %s' % e)
            self.debug('using default value (%s) for settings/maxlevel' % self.settings['maxlevel'])

        try:
            self.settings['reason'] = self.config.get('settings', 'reason')
            self.debug('loaded settings/reason: %s' % self.settings['reason'])
        except NoOptionError:
            self.warning('could not find settings/reason in config file, using default: %s' % self.settings['reason'])

        try:
            self.settings['timeout'] = self.config.getint('settings', 'timeout')
            self.debug('loaded settings/timeout: %s' % self.settings['timeout'])
        except NoOptionError:
            self.warning('could not find settings/timeout in config file, using default: %s' % self.settings['timeout'])
        except ValueError, e:
            self.error('could not load settings/timeout config value: %s' % e)
            self.debug('using default value (%s) for settings/timeout' % self.settings['timeout'])

        try:
            for s in self.config.options('services'):
                if s not in self.settings['services']:
                    self.warning('invalid proxy scanner service found in configuration file: %s' % s)
                else:
                    try:
                        self.settings['services'][s]['enabled'] = self.config.getboolean('services', s)
                        self.debug('using proxy scanner [%s] : %s' % (s, self.settings['services'][s]['enabled']))
                    except ValueError, e:
                        self.error('could not load services/%s configuration value: %s' % (s, e))
                        self.debug('using proxy scanner [%s] : %s' % (s, self.settings['services'][s]['enabled']))
        except NoSectionError:
            # all the proxy scanners will be used
            self.warning('section "services" missing in configuration file: using default configuration')

    def onStartup(self):
        """
        Initialize plugin settings.
        """
        # create database tables (if needed)
        if 'proxies' not in self.console.storage.getTables():
            external_dir = self.console.config.get_external_plugins_dir()
            sql_path = os.path.join(external_dir, 'proxyfilter', 'sql', self.console.storage.dsnDict['protocol'], 'proxyfilter.sql')
            self.console.storage.queryFromFile(sql_path)

        # register our commands
        if 'commands' in self.config.sections():
            for cmd in self.config.options('commands'):
                level = self.config.get('commands', cmd)
                sp = cmd.split('-')
                alias = None
                if len(sp) == 2:
                    cmd, alias = sp

                func = getCmd(self, cmd)
                if func:
                    self.adminPlugin.registerCommand(self, cmd, level, func, alias)

        # create proxy scanner instances
        for keyword in self.settings['services']:
            if self.settings['services'][keyword]['enabled']:
                self.init_proxy_service(keyword)

        if 'geolocation' in self.services:
            self.registerEvent('EVT_CLIENT_GEOLOCATION_SUCCESS', self.doProxyScan)
            self.registerEvent('EVT_CLIENT_GEOLOCATION_FAILURE', self.doProxyScan)
        else:
            self.registerEvent(self.console.getEventID('EVT_CLIENT_AUTH'), self.doProxyScan)

        # notice plugin started
        self.debug('plugin started')

    ####################################################################################################################
    #                                                                                                                  #
    #   EVENTS                                                                                                         #
    #                                                                                                                  #
    ####################################################################################################################

    def _threaded_proxy_scan(self, client):
        """
        Perform proxy server detection on the given client.
        Will be executed in a separate thread so B3 won't hang on checking.
        """
        for k in self.services:
            if self.services[k].scan(client):
                self.log_proxy_connection(k, client)
                client.kick(reason=self.settings['reason'], silent=True)
                self.console.say(self.getMessage('client_rejected', {'client': client.name}))
                return

        self.debug('proxy scan completed for %s <@%s> : no proxy detected' % (client.name, client.id))

    def doProxyScan(self, event):
        """
        Handle EVT_CLIENT_AUTH.
        """
        client = event.client
        if client.maxLevel >= self.settings['maxlevel']:
            self.debug('bypassing proxy scan for %s <@%s> : he is a high group level player' % (client.name, client.id))
        else:
            proxycheck = Thread(target=self._threaded_proxy_scan, args=(client,))
            proxycheck.setDaemon(True)
            proxycheck.start()

    ####################################################################################################################
    #                                                                                                                  #
    #   OTHER METHODS                                                                                                  #
    #                                                                                                                  #
    ####################################################################################################################

    def log_proxy_connection(self, service, client):
        """
        Log a proxy connection in the database
        """
        self.console.storage.query(self.sql['q1'] % (client.id, service, client.ip, time()))
        self.debug('stored new proxy connection for %s <@%s> : [%s] %s' % (client.name, client.id, service, client.ip))

    def init_proxy_service(self, keyword):
        """
        Initialize a proxy scanner service instance.
        """
        try:
            self.debug('initializing proxy scanner service: %s...' % keyword)
            obj = self.settings['services'][keyword]['class'](self, keyword, self.settings['services'][keyword]['url'])
            self.services[keyword] = obj
            return True
        except Exception, e:
            self.warning('could not initialize proxy scanner service [%s]: %s' % (keyword, e))
            return False

    ####################################################################################################################
    #                                                                                                                  #
    #   COMMANDS                                                                                                       #
    #                                                                                                                  #
    ####################################################################################################################

    def cmd_proxylist(self, data, client, cmd=None):
        """
        Display the list of available proxy checker services
        """
        services = []
        for k in self.settings['services']:
            enabled = self.settings['services'][k]['enabled']
            services.append('%s%s' % ('^2' if enabled else '^1',k))
        cmd.sayLoudOrPM(client, self.getMessage('proxy_list', {'services': '^7, '.join(services)}))

    def cmd_proxyservice(self, data, client, cmd=None):
        """
        <service> <on|off> - enable/disable a proxy scanner service
        """
        if not data:
            client.message('^7missing data, try ^3!^7help proxyservice')
            return

        r = re.compile(r'''^(?P<service>\w+)\s+(?P<option>on|off)$''')
        m = r.match(data)
        if not m:
            client.message('^7invalid data, try ^3!^7help proxyservice')
            return

        # get the service
        service = m.group('service')
        service = service.lower()

        if service not in self.settings['services']:
            client.message('^7invalid service specified, try ^3!^7proxylist')
            return

        # get the option
        option = m.group('option')
        option = option.lower()

        if option == 'on':

            # if already operational
            if service in self.services:
                client.message('^7proxy service ^3%s ^7is already ^2ON' % service)
                return

            if self.init_proxy_service(service):
                # successfully started
                client.message('^7proxy service ^3%s ^7is now ^2ON' % service)
                self.settings['services'][service]['enabled'] = True
            else:
                client.message('^7could not bring up proxy service ^1%s' % service)
                client.message('^7check the B3 log file for detailed information')

        elif option == 'off':

            # if not operational
            if service not in self.services:
                client.message('^7proxy service ^3%s ^7is already ^1OFF' % service)
                return

            # shut it down
            del self.services[service]
            self.settings['services'][service]['enabled'] = False
            client.message('^7proxy service ^3%s ^7is now ^1OFF' % service)

    def cmd_proxystats(self, data, client, cmd=None):
        """
        Display statistics about detected proxies
        """
        cursor = self.console.storage.query(self.sql['q2'])
        cmd.sayLoudOrPM(client, self.getMessage('stats_count_proxies', {'count': cursor.getRow()['total']}))
        cursor.close()

        cursor = self.console.storage.query(self.sql['q3'])
        while not cursor.EOF:
            r = cursor.getRow()
            cmd.sayLoudOrPM(client, self.getMessage('stats_detail_pattern', {'count': r['total'], 'service': r['service']}))
            cursor.moveNext()
        cursor.close()