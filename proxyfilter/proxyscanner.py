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


from b3.exceptions import MissingRequirement
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
    #                                                                                                                  #
    #   CUSTOM LOGGING METHODS                                                                                         #
    #                                                                                                                  #
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
#                                                                                                                      #
#   WINMXUNLIMITED.NET                                                                                                 #
#                                                                                                                      #
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
#                                                                                                                      #
#   GEOLOCATION PLUGIN BASED SCANNER                                                                                      #
#                                                                                                                      #
########################################################################################################################


class GeolocationPluginProxyScanner(ProxyScanner):
    """
    Perform proxy detection using information retrieved by the GeolocationPlugin.
    """
    locationPlugin = None

    def __init__(self, plugin, service, url):
        """
        Object constructor.
        """
        if not plugin.console.getPlugin('geolocation'):
            raise MissingRequirement('geolocation plugin is not available')
        super(GeolocationPluginProxyScanner, self).__init__(plugin, service, url)

    def scan(self, client):
        """
        Return True if the given client is connected through a Proxy server, False otherwise.
        """
        if not hasattr(client, 'location'):
            self.debug('could not perform proxy scan on %s <@%s> : geolocation data not available' % (client.name, client.id))
            return False

        if 'proxy' in client.location.country.lower():
            self.debug('%s <@%s> detected as using a proxy: %s' % (client.name, client.id, client.ip))
            return True

        self.debug('%s <@%s> doesn\'t seems to be using a proxy' % (client.name, client.id))
        return False