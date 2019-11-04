#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')

from test_vtest_common import *
import vtconst
import pytest

# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test

class TestClass(vTestCommon, object):
    @classmethod
    def setup_method(cls, method):
        super(TestClass, cls).setUpClass(method)

    @classmethod
    def teardown_method(cls, method):
        super(TestClass, cls).tearDownClass(method)

    def test_1(self):
        uf = util_functions()
        vif = uf.create_vif(1, None, "tap_1", None, vt_ipv4('1.1.1.10'), vt_mac('de:ad:be:ef:00:02'), None, ip6_u=72340172838076673, ip6_l=18374403900871474942)
        print(vif)
        uf.send_sandesh_req(vif)
        vif1 = uf.create_vif(1, None, None, None, None, None, None, None, None, h_op=vtconst.SANDESH_OPER_GET)
        vif_resp_file = uf.send_sandesh_req(vif1, uf.VT_RESPONSE_REQD) 
        # parse the fields and validate the response
        vif_name = uf.parse_xml_field(vif_resp_file, "vifr_name")
        print "Got vif name ", vif_name
        assert (vif_name.find("tap_1") != -1), "Failed to get vif name"
        vif_mtu = uf.parse_xml_field(vif_resp_file, "vifr_mtu")
        print "Got vif mtu ", vif_mtu
        assert (vif_mtu.find("1514") != -1), "Failed to get mtu value"
        print "Test 1 passed"
       
        return 0
