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
from mock import call
from mockito import when
from textwrap import dedent
from tests import ProxyfilterTestCase
from tests import logging_disabled
from proxyfilter import ProxyfilterPlugin
from time import sleep


class Test_events(ProxyfilterTestCase):

    def setUp(self):
        ProxyfilterTestCase.setUp(self)

        self.conf = CfgConfigParser()
        self.conf.loadFromString(dedent(r"""
            [settings]
            maxlevel: reg
            reason: ^1proxy detected
            timeout: 4

            [services]
            winmxunlimited: yes
            locationplugin: no

            [messages]
            client_rejected: ^7$client has been ^1rejected^7: proxy detected
            proxy_list: ^7Proxy services: $services
            stats_no_proxies: ^7No proxies have been detected till now
            stats_count_proxies: ^2$count ^7proxy have been detected till now
            stats_detail_pattern: ^7[^4$count^7] ^7: ^3$service

            [commands]
            proxylist: senioradmin
            proxyservice: senioradmin
            proxystats: senioradmin
        """))

        self.p = ProxyfilterPlugin(self.console, self.conf)
        self.p.onLoadConfig()
        self.p.onStartup()

        with logging_disabled():
            from b3.fake import FakeClient

        # create some fake clients
        self.mike = FakeClient(console=self.console, name="Mike", guid="mikeguid", ip="127.0.0.1", groupBits=1)
        self.bill = FakeClient(console=self.console, name="Bill", guid="billguid", ip="127.0.0.2", groupBits=2)

    ####################################################################################################################
    ##                                                                                                                ##
    ##  TEST EVENT CLIENT CONNECT                                                                                     ##
    ##                                                                                                                ##
    ####################################################################################################################

    def test_event_client_connect_proxy_detected(self):
        # GIVEN
        self.mike.kick = Mock()
        # WHEN
        when(self.p.services['winmxunlimited']).scan(self.mike).thenReturn(True)
        self.mike.connects("1")
        sleep(.5)
        # THEN
        self.mike.kick.assert_has_calls(call(reason='^1proxy detected', silent=True))
        self.assertEqual(1, self.p.console.storage.query(self.p.sql['q2']).getRow()['total'])

    def test_event_client_connect_proxy_not_detected(self):
        # GIVEN
        self.p.debug = Mock()
        # WHEN
        when(self.p.services['winmxunlimited']).scan(self.mike).thenReturn(False)
        self.mike.connects("1")
        sleep(.5)
        # THEN
        self.p.debug.assert_has_calls(call('proxy scan completed for Mike <@1> : no proxy detected'))
        self.assertEqual(0, self.p.console.storage.query(self.p.sql['q2']).getRow()['total'])

    def test_event_client_connect_proxy_bypass(self):
        # GIVEN
        self.p.debug = Mock()
        # WHEN
        self.bill.connects("1")
        sleep(.5)
        # THEN
        self.p.debug.assert_has_calls(call('bypassing proxy scan for Bill <@1> : he is a high group level player'))
        self.assertEqual(0, self.p.console.storage.query(self.p.sql['q2']).getRow()['total'])

    ####################################################################################################################
    ##                                                                                                                ##
    ##  TEST PLUGIN ENABLE                                                                                            ##
    ##                                                                                                                ##
    ####################################################################################################################

    #def test_plugin_enabled(self):
    #    # GIVEN
    #    self.p.disable()
    #    self.mike.kick = Mock()
    #    # WHEN
    #    when(self.p.services['winmxunlimited']).scan(self.mike).thenReturn(True)
    #    self.mike.connects("1")
    #    self.p.enable()
    #    # THEN
    #    self.mike.kick.assert_has_calls(call(reason='^1proxy detected', silent=True))
    #    self.assertEqual(1, self.p.console.storage.query(self.p.sql['q2']).getRow()['total'])