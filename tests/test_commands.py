#
# Location Plugin for BigBrotherBot(B3) (www.bigbrotherbot.net)
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
from mock import Mock
from mockito import when
from textwrap import dedent
from tests import ProxyfilterTestCase
from tests import logging_disabled
from proxyfilter import ProxyfilterPlugin
from proxyfilter import WinmxunlimitedProxyScanner


class Test_commands(ProxyfilterTestCase):

    def setUp(self):
        ProxyfilterTestCase.setUp(self)

        with logging_disabled():
            from b3.fake import FakeClient

        # create some fake clients
        self.mike = FakeClient(console=self.console, name="Mike", guid="mikeguid", ip="127.0.0.1", groupBits=128)
        self.bill = FakeClient(console=self.console, name="Bill", guid="billguid", ip="127.0.0.2", groupBits=1)

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

        self.p.services = {} ## DO NOT REMOVE THIS!!!!!!
        self.p.onLoadConfig()
        self.p.onStartup()

    ####################################################################################################################
    ##                                                                                                                ##
    ##  TEST CMD PROXYLIST                                                                                            ##
    ##                                                                                                                ##
    ####################################################################################################################

    def test_cmd_proxylist(self):
        # GIVEN
        self.init()
        # WHEN
        self.mike.connects("1")
        self.mike.clearMessageHistory()
        self.mike.says("!proxylist")
        # THEN
        self.assertListEqual(['Proxy services: winmxunlimited'], self.mike.message_history)

    ####################################################################################################################
    ##                                                                                                                ##
    ##  TEST CMD PROXYSERVICE                                                                                         ##
    ##                                                                                                                ##
    ####################################################################################################################

    def test_cmd_proxyservice_missing_data(self):
        # GIVEN
        self.init()
        # WHEN
        self.mike.connects("1")
        self.mike.clearMessageHistory()
        self.mike.says("!proxyservice")
        # THEN
        self.assertListEqual(['missing data, try !help proxyservice'], self.mike.message_history)

    def test_cmd_proxyservice_invalid_data(self):
        # GIVEN
        self.init()
        # WHEN
        self.mike.connects("1")
        self.mike.clearMessageHistory()
        self.mike.says("!proxyservice winmxunlimited status")
        # THEN
        self.assertListEqual(['invalid data, try !help proxyservice'], self.mike.message_history)

    def test_cmd_proxyservice_invalid_service(self):
        # GIVEN
        self.init()
        # WHEN
        self.mike.connects("1")
        self.mike.clearMessageHistory()
        self.mike.says("!proxyservice fakeproxy on")
        # THEN
        self.assertListEqual(['invalid service specified, try !proxylist'], self.mike.message_history)

    def test_cmd_proxyservice_on(self):
        # GIVEN
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
        # WHEN
        self.mike.connects("1")
        self.mike.clearMessageHistory()
        self.mike.says("!proxyservice winmxunlimited on")
        # THEN
        self.assertListEqual(['proxy service winmxunlimited is now ON'], self.mike.message_history)
        self.assertEqual(True, 'winmxunlimited' in self.p.services.keys())
        self.assertIsInstance(self.p.services['winmxunlimited'], WinmxunlimitedProxyScanner)

    def test_cmd_proxyservice_on_already_on(self):
        # GIVEN
        self.init()
        # WHEN
        self.mike.connects("1")
        self.mike.clearMessageHistory()
        self.mike.says("!proxyservice winmxunlimited on")
        # THEN
        self.assertListEqual(['proxy service winmxunlimited is already ON'], self.mike.message_history)
        self.assertEqual(True, 'winmxunlimited' in self.p.services.keys())
        self.assertIsInstance(self.p.services['winmxunlimited'], WinmxunlimitedProxyScanner)

    def test_cmd_proxyservice_off(self):
        # GIVEN
        self.init()
        # WHEN
        self.mike.connects("1")
        self.mike.clearMessageHistory()
        self.mike.says("!proxyservice winmxunlimited off")
        # THEN
        self.assertListEqual(['proxy service winmxunlimited is now OFF'], self.mike.message_history)
        self.assertDictEqual({}, self.p.services)

    def test_cmd_proxyservice_off_already_off(self):
        # GIVEN
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
        # WHEN
        self.mike.connects("1")
        self.mike.clearMessageHistory()
        self.mike.says("!proxyservice winmxunlimited off")
        # THEN
        self.assertListEqual(['proxy service winmxunlimited is already OFF'], self.mike.message_history)
        self.assertDictEqual({}, self.p.services)

    ####################################################################################################################
    ##                                                                                                                ##
    ##  TEST CMD PROXYSTATS                                                                                           ##
    ##                                                                                                                ##
    ####################################################################################################################

    def test_cmd_proxystats_empty(self):
        # GIVEN
        self.init()
        # WHEN
        self.mike.connects("1")
        self.mike.clearMessageHistory()
        self.mike.says("!proxystats")
        # THEN
        self.assertListEqual(['[0] proxy detected till now'], self.mike.message_history)

    def test_cmd_proxystats_with_result(self):
        # GIVEN
        self.init()
        self.bill.kick = Mock()
        # WHEN
        when(self.p.services['winmxunlimited']).scan(self.bill).thenReturn(True)
        self.mike.connects("1")
        self.bill.connects("2")
        self.mike.clearMessageHistory()
        self.mike.says("!proxystats")
        # THEN
        self.assertListEqual(['[1] proxy detected till now',
                              '[1] : winmxunlimited'], self.mike.message_history)