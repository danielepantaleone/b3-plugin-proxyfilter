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


import logging
import unittest2
import os

from mockito import when
from b3.config import MainConfig
from b3.config import CfgConfigParser
from b3.plugins.admin import AdminPlugin
from proxyfilter import ProxyfilterPlugin


def patch_proxy_filter():
    """
    Patch the Proxyfilter class not to execute proxy scans in a thread
    """
    def proxy_scan(self, client):
        self._threaded_proxy_scan(client)

    ProxyfilterPlugin.proxy_check = proxy_scan

class logging_disabled(object):
    """
    Context manager that temporarily disable logging.

    USAGE:
        with logging_disabled():
            # do stuff
    """
    DISABLED = False

    def __init__(self):
        self.nested = logging_disabled.DISABLED

    def __enter__(self):
        if not self.nested:
            logging.getLogger('output').propagate = False
            logging_disabled.DISABLED = True

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self.nested:
            logging.getLogger('output').propagate = True
            logging_disabled.DISABLED = False


class ProxyfilterTestCase(unittest2.TestCase):

    def setUp(self):
        # create a FakeConsole parser
        self.parser_conf = MainConfig(CfgConfigParser(allow_no_value=True))
        self.parser_conf.loadFromString(r"""""")
        with logging_disabled():
            from b3.fake import FakeConsole
            self.console = FakeConsole(self.parser_conf)

        # load the admin plugin
        with logging_disabled():
            self.adminPlugin = AdminPlugin(self.console, '@b3/conf/plugin_admin.ini')
            self.adminPlugin._commands = {}
            self.adminPlugin.onStartup()

        # make sure the admin plugin obtained by other plugins is our admin plugin
        when(self.console).getPlugin('admin').thenReturn(self.adminPlugin)
        when(self.console.config).get_external_plugins_dir().thenReturn(os.path.join(os.getcwd(), '..', 'extplugins'))

        # patch the Proxyfilter class not to execute
        # proxy scans in a multithreaded environment
        patch_proxy_filter()

    def tearDown(self):
        self.console.working = False