#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')

from test_vtest_common import *
import vtconst
import pytest
import inspect

class TestClass(vTestCommon, object):
    @classmethod
    def setup_method(cls, method):
        super(TestClass, cls).setUpClass(method)

    @classmethod
    def teardown_method(cls, method):
        super(TestClass, cls).tearDownClass(method)
    
    def test_vif(self):
        uf = util_functions()
        vif = uf.create_vif(1, None, "tap_1", None, vt_ipv4('1.1.1.10'), vt_mac('de:ad:be:ef:00:02'), None, ip6_u=72340172838076673, ip6_l=18374403900871474942)
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

    def test_encap_nh(self):
        uf = util_functions()
        vif = uf.create_vif(1, None, "tap_1", None, vt_ipv4('1.1.1.10'), vt_mac('de:ad:be:ef:00:02'), None, ip6_u=72340172838076673, ip6_l=18374403900871474942)
        print inspect.getmro(vif.__class__)
        uf.send_sandesh_req(vif)
        e_nh1 = uf.create_encap_nh(1, 1, vt_encap("de ad be ef 00 02 de ad be ef 00 01 08 00"), 0, 1, vtconst.AF_INET)
        print inspect.getmro(e_nh1.__class__)
        uf.send_sandesh_req(e_nh1)

        e_nh1.h_op = vtconst.SANDESH_OPER_GET
        nh_resp = uf.send_sandesh_req(e_nh1, uf.VT_RESPONSE_REQD)
        nh_id = uf.parse_xml_field(nh_resp, "nhr_id")
        print "Got nh id", nh_id
        assert (nh_id.find("1") != -1), "Failed to get nh_id value"
        print "Test encap_nh passed"
        return 0
