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

from time import sleep
from urllib2 import urlopen
from urllib2 import URLError

class ProxyScanner(object):
    """
    Base class for Proxy scanners
    """
    def __init__(self, plugin, service, url):
        """
        Object constructor.
        """
        self.p = plugin
        self.service = service
        self.url = url

    def scan(self, client):
        """
        !!! Inheriting classes MUST implement this method !!!
        """
        raise NotImplementedError

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
        Return True if the given client is connected through a Proxy server, False otherwise.
        """
        try:

            self.debug("contacting service api to check proxy connection for %s <@%s>..." % (client.name, client.id))
            response = urlopen(url=self.url % client.ip, timeout=self.p.settings['timeout'])
            data = response.read().strip()

            if data == self.responses['INVALID_IP']:
                self.warning('invalid ip address supplied to the service api : <@%s:%s>' % (client.id, client.ip))
                return False

            if data == self.responses['PUBLIC_PROXY']:
                self.debug('%s <@%s> detected as using a "public" proxy: %s' % (client.name, client.id, client.ip))
                return True

            if data == self.responses['TOR_PROXY']:
                self.debug('%s <@%s> detected as using a "tor" proxy: %s' % (client.name, client.id, client.ip))
                return True

            if data == self.responses['NO_PROXY']:
                self.debug('%s <@%s> doesn\'t seems to be using a proxy' % (client.name, client.id))
                return False

            self.warning('invalid response returned from the service api: %s' % data)
            return False

        except URLError, e:
            self.error('could not connect to service api: %s' % e)
            return False


########################################################################################################################
##                                                                                                                    ##
##   LOCATION PLUGIN BASED SCANNER                                                                                    ##
##                                                                                                                    ##
########################################################################################################################


class LocationPluginProxyScanner(ProxyScanner):
    """
    Perform proxy detection using information retrieved by the LocationPlugin.
    """
    locationPlugin = None

    def __init__(self, plugin, service, url):
        """
        Object constructor.
        """
        ProxyScanner.__init__(self, plugin, service, url)
        self.locationPlugin = self.p.console.getPlugin('location')
        if not self.locationPlugin:
            raise Exception('LocationPlugin is not available')

    def scan(self, client):
        """
        Return True if the given client is connected through a Proxy server, False otherwise.
        """
        if not client.isvar(self.locationPlugin, 'location'):
            # location plugin still didn't manage to retrieve location information so sleep a bit and give it time
            # this won't hang B3 since everything is executed in a separate thread
            sleep(10)
            if not client.isvar(self.locationPlugin, 'location'):
                self.debug('could not perform proxy scan on %s <@%s> : location data not available' % (client.name, client.id))
                return False

        # get the location from the client object
        location = client.var(self.locationPlugin, 'location').value

        if location['country'] == 'Anonymous Proxy':
            self.debug('%s <@%s> detected as using an "anonymous" proxy: %s' % (client.name, client.id, client.ip))
            return True

        self.debug('%s <@%s> doesn\'t seems to be using a proxy' % (client.name, client.id))
        return False