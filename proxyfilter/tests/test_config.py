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

from b3.config import CfgConfigParser
from textwrap import dedent
from . import ProxyfilterTestCase
from proxyfilter import ProxyfilterPlugin
from proxyfilter import WinmxunlimitedProxyScanner


class Test_config(ProxyfilterTestCase):

    def setUp(self):
        ProxyfilterTestCase.setUp(self)

    def init(self, config_content=None):
        self.conf = CfgConfigParser()
        self.p = ProxyfilterPlugin(self.console, self.conf)
        if config_content:
            self.conf.loadFromString(config_content)
        else:
            self.conf.loadFromString(dedent(r"""
                [settings]
                maxlevel: reg
                reason: ^1proxy detected
                timeout: 4

                [services]
                winmxunlimited: yes

                [messages]
                client_rejected: ^7$client has been ^1rejected^7: proxy detected
                proxy_list: ^7Proxy services: $services
                stats_count_proxies: ^7[^4$count^7] ^7proxy detected till now
                stats_detail_pattern: ^7[^4$count^7] ^7: ^3$service

                [commands]
                proxylist: senioradmin
                proxyservice: senioradmin
                proxystats: senioradmin
            """))

        self.p.onLoadConfig()
        self.p.onStartup()

    ####################################################################################################################
    ##                                                                                                                ##
    ##  TEST CMD PROXYLIST                                                                                            ##
    ##                                                                                                                ##
    ####################################################################################################################

    def test_config_service_disabled(self):
        # WHEN
        self.init(dedent(r"""
            [settings]
            maxlevel: reg
            reason: ^1proxy detected
            timeout: 4

            [services]
            winmxunlimited: no

            [messages]
            client_rejected: ^7$client has been ^1rejected^7: proxy detected
            proxy_list: ^7Proxy services: $services
            stats_count_proxies: ^7[^4$count^7] ^7proxy detected till now
            stats_detail_pattern: ^7[^4$count^7] ^7: ^3$service

            [commands]
            proxylist: senioradmin
            proxyservice: senioradmin
            proxystats: senioradmin
        """))
        # THEN
        self.assertDictEqual({}, self.p.services)
        self.assertListEqual(['geolocationplugin', 'winmxunlimited'], self.p.settings['services'].keys())

    def test_config_service_enabled(self):
        # WHEN
        self.init()
        # THEN
        self.assertEqual(True, 'winmxunlimited' in self.p.services.keys())
        self.assertIsInstance(self.p.services['winmxunlimited'], WinmxunlimitedProxyScanner)