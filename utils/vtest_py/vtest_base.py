#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import pytest
import testtools
import fixtures
import logging
from vr_py_sandesh.vr_py.ttypes import *
from pysandesh.transport.TTransport import *
from pysandesh.protocol.TProtocol import *
from pysandesh.protocol.TXMLProtocol import *

class TestCase(testtools.TestCase, fixtures.TestWithFixtures):
    def __init__(self, *args, **kwargs):
        super(TestCase, self).__init__(*args, **kwargs)
        self._logger = logging.getLogger(__name__)
        self._auto_cleanup = True

    @classmethod
    def setUpClass(cls):
        super(TestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCase, cls).setUpClass()

    def setUp(self):
        super(TestCase, self).setUp()
        self._logger.info("Running %s" %(self.id()))

    def tearDown(self):
        super(TestCase, self).tearDown()

    @property
    def auto_cleanup(self):
        return self._auto_cleanup

    @auto_cleanup.setter
    def set_auto_cleanup(self, cleanup):
        self._auto_cleanup = cleanup

# Need to have functionality to start/stop vrouter and vtest
class VTestBase(TestCase):
    def __init__(self, *args, **kwargs):
        super(VTestBase, self).__init__(*args, **kwargs)

    def setUpClass(self):
        super(VTestBase, self).setUpClass()
        _vrouter_args = self.get_vrouter_args()
        self.launch_vrouter_instance(_vrouter_args)

    def tearDownClass(self):
        super(VTestBase, self).setUpClass()
        self._logger.info("Running %s" %(self.id()))
        self.kill_vrouter_instance() 

    def setUp(self):
        super(VTestBase, self).setUp()
        self._logger.info("Running %s" %(self.id()))
        self.vtest_ut_init()

    def tearDown(self):
        super(VTestBase, self).tearDown()
        self.vtest_ut_cleanup()

    def get_vrouter_args(self):
        sb_path = '../../../../../build'
        vr_args['vrouter_path'] = sb_path + '/debug/vrouter/dpdk/contrail-vrouter-dpdk'
        vr_args['socket_dir'] = sb_path + '/debug/vrouter/utils/vtest_py_venv/var/run/vrouter'
        vr_args['vtest_only'] = int(os.environ['VTEST_ONLY_MODE'])
        vr_args['taskset'] = '0x6'
        return vr_args

    def get_vtest_args(self):
        sb_path = '../../../../../build'
        vr_args['vtest_path'] = sb_path + '/debug/vrouter/utils/vtest'
        return vt_args

    def launch_vrouter_instance(self):
        # Add code to start vrouter
        pass

    def kill_vrouter_instance(self):
        # Add code to stop vrouter
        pass

    def vtest_ut_init(self):
        # Add code to prepare vtest 
        # Cleanup temp files, create new UT directory etc.
        pass

    def vtest_ut_cleanup(self):
        pass

    # Generic run command
    def run_command(self, cmd):
        # Add code to run the command
        return os.popen(cmd).read()
