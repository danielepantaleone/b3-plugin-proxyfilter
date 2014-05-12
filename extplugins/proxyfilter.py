#
# ProxyFilter Plugin for BigBrotherBot(B3) (www.bigbrotherbot.net)
# Copyright (C) 2013 Daniele Pantaleone <fenix@bigbrotherbot.net>
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
#   2014/05/12 - 1.0 - Fenix
#   * initial release

__author__ = 'Fenix'
__version__ = '1.0'

import b3
import b3.plugin
import b3.events
import threading
import time
import re

from urllib2 import urlopen
from urllib2 import URLError
from ConfigParser import NoOptionError
from ConfigParser import NoSectionError

try:
    # import the getCmd function
    import b3.functions.getCmd as getCmd
except ImportError:
    # keep backward compatibility
    def getCmd(instance, cmd):
        cmd = 'cmd_%s' % cmd
        if hasattr(instance, cmd):
            func = getattr(instance, cmd)
            return func
        return None


########################################################################################################################
##                                                                                                                    ##
##   PROXY CHECKERS DEDICATED CODE                                                                                    ##
##                                                                                                                    ##
########################################################################################################################


class ProxyScanner(object):
    """
    Base class for Proxy checkers
    """
    def __init__(self, plugin, service, url):
        """
        Object constructor
        """
        self.p = plugin
        self.service = service
        self.url = url

    def scan(self, client):
        """
        !!! Inheriting classes MUST implement this method !!!
        """
        return False

    ####################################################################################################################
    ##                                                                                                                ##
    ##   CUSTOM LOGGING METHODS                                                                                       ##
    ##                                                                                                                ##
    ####################################################################################################################

    def debug(self, msg, *args, **kwargs):
        """
        Log a DEBUG message
        """
        self.p.debug('[%s] %s' % (self.service, msg), *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        """
        Log a ERROR message
        """
        self.p.error('[%s] %s' % (self.service, msg), *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        """
        Log a WARNING message
        """
        self.p.warning('[%s] %s' % (self.service, msg), *args, **kwargs)


########################################################################################################################
##                                                                                                                    ##
##   WINMXUNLIMITED.NET                                                                                               ##
##                                                                                                                    ##
########################################################################################################################


class WinmxunlimitedProxyScanner(ProxyScanner):
    """
    Perform proxy detection using winmxunlimited.net API
    """
    responses = {
        'INVALID_IP': 'Invalid IP',
        'PUBLIC_PROXY': 'Public',
        'TOR_PROXY': 'Tor',
        'NO_PROXY': '0',
    }

    def scan(self, client):
        """
        Return True if the given client is connected
        through a Proxy server, False otherwise
        """
        try:
            self.debug("contacting service api to check proxy connection for client <@%s>..." % client.id)
            response = urlopen(url=self.url % client.ip, timeout=self.p.settings['timeout'])
            data = response.read().strip()

            if data == self.responses['INVALID_IP']:
                self.warning('invalid ip address supplied to the service api : <@%s:%s>' % (client.id, client.ip))
                return False

            if data == self.responses['PUBLIC_PROXY']:
                self.debug('client <@%s> detected as using a "public" proxy: %s' % (client.id, client.ip))
                return True

            if data == self.responses['TOR_PROXY']:
                self.debug('client <@%s> detected as using a "tor" proxy: %s' % (client.id, client.ip))
                return True

            if data == self.responses['NO_PROXY']:
                self.debug('client <@%s> doesn\'t seems to be using a proxy')
                return False

            self.error('invalid response returned from the service api: %s' % data)
            return False

        except URLError, e:
            self.error('could not connect to service api: %s' % e)
            return False


########################################################################################################################
##                                                                                                                    ##
##   PLUGIN IMPLEMENTATION                                                                                            ##
##                                                                                                                    ##
########################################################################################################################


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
            }
        }
    }

    sql = {
        ## DATA STORAGE/RETRIEVAL
        'q1': """INSERT INTO proxies VALUES (NULL, '%s', '%s', '%s', '%d')""",
        'q2': """SELECT COUNT(DISTINCT ip) AS total FROM proxies""",
        'q3': """SELECT service, COUNT(*) AS total FROM proxies GROUP BY service ORDER BY service ASC""",

        ## DATABASE SETUP
        'mysql': """CREATE TABLE IF NOT EXISTS proxies (
                        id int(10) unsigned NOT NULL AUTO_INCREMENT,
                        client_id int(10) unsigned NOT NULL,
                        service varchar(64) NOT NULL,
                        ip varchar(15) NOT NULL,
                        time_add int(10) unsigned NOT NULL,
                        PRIMARY KEY (id)
                    ) ENGINE=MyISAM DEFAULT CHARSET=utf8 AUTO_INCREMENT=1;""",
        'sqlite': """CREATE TABLE IF NOT EXISTS proxies (
                         id INTEGER PRIMARY KEY AUTOINCREMENT,
                         client_id INTEGER(10) NOT NULL,
                         service VARCHAR(64) NOT NULL,
                         ip VARCHAR(15) NOT NULL,
                         time_add INTEGER(10) NOT NULL);"""
    }

    services = {}

    ####################################################################################################################
    ##                                                                                                                ##
    ##   STARTUP                                                                                                      ##
    ##                                                                                                                ##
    ####################################################################################################################

    def __init__(self, console, config=None):
        """
        Build the plugin object
        """
        b3.plugin.Plugin.__init__(self, console, config)

        # get the admin plugin
        self.adminPlugin = self.console.getPlugin('admin')
        if not self.adminPlugin:
            self.critical('could not start without admin plugin')
            raise SystemExit(220)

        # set default messages
        self._default_messages = {
            'client_rejected': '''^7$client has been ^1rejected^7: proxy detected''',
            'proxy_list': '''^7Proxy services: $services''',
            'stats_no_proxies': '''^7No proxy have been detected till now''',
            'stats_count_proxies': '''^^7[^4$count^7] ^7proxy detected till now''',
            'stats_detail_pattern': '''^7[^4$count^7] ^7: ^3$service'''
        }

    def onLoadConfig(self):
        """
        Load plugin configuration
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

             # load proxy checker services settings
            for s in self.config.options('services'):
                if not s in self.settings['services'].keys():
                    self.warning('invalid proxy checker service found in configuration file: %s' % s)
                    continue
                try:
                    self.settings['services'][s]['enabled'] = self.config.getboolean('services', s)
                    self.debug('using proxy checker service [%s] : %s' % (s, self.settings['services'][s]['enabled']))
                except ValueError, e:
                    self.error('could not load services/%s configuration value: %s' % (s, e))
                    self.debug('using proxy checker service [%s] : %s' % (s, self.settings['services'][s]['enabled']))

        except NoSectionError:
            # all the proxy checker services will be used
            self.warning('section "services" missing in configuration file: using default configuration')

    def onStartup(self):
        """
        Initialize plugin settings
        """
        # create database tables (if needed)
        if not 'proxies' in self.getTables():
            protocol = self.console.storage.dsnDict['protocol']
            self.console.storage.query(self.sql[protocol])

        # create proxy checker instances
        for keyword in self.settings['services'].keys():
            if self.settings['services'][keyword]['enabled']:
                self.init_proxy_service(keyword)

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

        try:
            # register the events needed
            self.registerEvent(self.console.getEventID('EVT_CLIENT_CONNECT'), self.onConnect)
        except TypeError:
            # keep backwards compatibility: B3 <= 1.9.x
            self.registerEvent(self.console.getEventID('EVT_CLIENT_CONNECT'))

        # notice plugin started
        self.debug('plugin started')

        # check connected clients on bot startup
        for client in self.console.clients.getList():
            if client.maxLevel >= self.settings['maxlevel']:
                self.debug('bypassing proxy detection for client <@%s>: he is a high group level player')
                return

            # scan the client for proxy usage
            self.proxy_check(client=client)

    ####################################################################################################################
    ##                                                                                                                ##
    ##   GET TABLES IMPLEMENTATION FOR B3 1.9.x RETROCOMPATIBILITY                                                    ##
    ##                                                                                                                ##
    ####################################################################################################################

    def getTables(self):
        """
        List the tables of the current database.
        :return: list of strings
        """
        tables = []
        protocol = self.console.storage.dsnDict['protocol']
        if protocol == 'mysql':
            q = """SHOW TABLES"""
        elif protocol == 'sqlite':
            q = """SELECT * FROM sqlite_master WHERE type='table'"""
        else:
            raise AssertionError("unsupported database %s" % protocol)
        cursor = self.console.storage.query(q)
        if cursor and not cursor.EOF:
            while not cursor.EOF:
                r = cursor.getRow()
                tables.append(r.values()[0])
                cursor.moveNext()
        return tables

    ####################################################################################################################
    ##                                                                                                                ##
    ##   EVENTS                                                                                                       ##
    ##                                                                                                                ##
    ####################################################################################################################

    def onEvent(self, event):
        """
        Old event dispatch system
        """
        if event.type == self.console.getEventID('EVT_CLIENT_CONNECT'):
            self.onConnect(event)

    def onEnable(self):
        """
        Executed when the plugin is enabled
        """
        for client in self.console.clients.getList():
            if client.maxLevel >= self.settings['maxlevel']:
                self.debug('bypassing proxy scan for client <@%s>: he is a high group level player')
                return

            # scan the client for proxy usage
            self.proxy_check(client=client)

    def onConnect(self, event):
        """
        Handle EVT_CLIENT_CONNECT
        """
        client = event.client
        if client.maxLevel >= self.settings['maxlevel']:
            self.debug('bypassing proxy scan for client <@%s>: he is a high group level player' % client.id)
            return

        # scan the connecting client for proxy usage
        self.proxy_check(client=client)

    ####################################################################################################################
    ##                                                                                                                ##
    ##   OTHER METHODS                                                                                                ##
    ##                                                                                                                ##
    ####################################################################################################################

    def log_proxy_connection(self, service, client):
        """
        Log a proxy connection in the database
        """
        self.console.storage.query(self.sql['q1'] % (client.id, service, client.ip, time.time()))
        self.debug('stored new proxy connection for client <@%s> : [%s] %s' % (client.id, service, client.ip))

    def init_proxy_service(self, keyword):
        """
        Initialize a proxy checker service instance
        """
        try:
            self.debug('initializing proxy checker service: %s...' % keyword)
            obj = self.settings['services'][keyword]['class'](self, keyword, self.settings['services'][keyword]['url'])
            self.services[keyword] = obj
            return True
        except Exception, e:
            self.error('could not initialize proxy checker service [%s]: %s' % (keyword, e))
            return False

    def proxy_check(self, client):
        """
        Will launch the proxy scan in a separate thread
        """
        proxycheck = threading.Thread(target=self.proxy_scan, args=(client,))
        proxycheck.setDaemon(True)
        proxycheck.start()

    def proxy_scan(self, client):
        """
        Perform proxy server detection on the given client
        Will be executed in a separate thread so B3 won't hang on checking
        """
        for k in self.services.keys():
            if self.services[k].scan(client):
                self.log_proxy_connection(k, client)
                client.kick(reason=self.settings['reason'], silent=True)
                self.console.say(self.getMessage('client_rejected', {'client': client.name}))
                return

        self.debug('proxy scan completed for client <@%s> : no proxy detected' % client.id)

    ####################################################################################################################
    ##                                                                                                                ##
    ##   COMMANDS                                                                                                     ##
    ##                                                                                                                ##
    ####################################################################################################################

    def cmd_proxylist(self, data, client, cmd=None):
        """
        Display the list of available proxy checker services
        """
        services = []
        for k in self.settings['services'].keys():
            enabled = self.settings['services'][k]['enabled']
            services.append('%s%s' % ('^2' if enabled else '^1',k))

        cmd.sayLoudOrPM(client, self.getMessage('proxy_list', {'services': '^7, '.join(services)}))

    def cmd_proxyservice(self, data, client, cmd=None):
        """
        <service> <on|off> - enable/disable a proxy checker service
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

        if not service in self.settings['services'].keys():
            client.message('^7invalid service specified, try ^3!^7proxylist')
            return

        # get the option
        option = m.group('option')
        option = option.lower()

        if option == 'on':

            # if already operational
            if service in self.services.keys():
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
            if service not in self.services.keys():
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