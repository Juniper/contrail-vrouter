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
        vif = uf.create_vif(1, 0, "tap_1", 0, vt_ipv4("1.1.1.10"), vt_mac("de:ad:be:ef:00:02"), 0)
        uf.send_sandesh_req(vif)

        vif = uf.create_vif(1, 0, "tap_1", 0, 0, [], 0, h_op=vtconst.SANDESH_OPER_GET)
        vif_resp_file = uf.send_sandesh_req(vif, uf.VT_RESPONSE_REQD)

        vif_name = uf.parse_xml_field(vif_resp_file, "vifr_name")
        print "Got vif name ", vif_name
        assert (vif_name.find("tap_1") != -1), "Failed to get vif name"
        vif_mtu = uf.parse_xml_field(vif_resp_file, "vifr_mtu")
        print "Got vif mtu ", vif_mtu
        assert (vif_mtu.find("1514") != -1), "Failed to get mtu value"
        print "Test vif passed"
        return 0
        
    def test_encap_nh(self):
        uf = util_functions()
        vif = uf.create_vif(1, 0, "en0", 0, vt_ipv4("192.168.1.1"), vt_mac("de:ad:be:ef:00:02"), 0) 
        uf.send_sandesh_req(vif)
        
        e_nh = uf.create_encap_nh(1, 1, vt_encap("de ad be ef 00 02 de ad be ef 00 01 08 00"), 0, vtconst.AF_INET, vtconst.NH_FLAG_VALID)
        uf.send_sandesh_req(e_nh)
  
        e_nh.h_op = vtconst.SANDESH_OPER_GET
        nh_resp = uf.send_sandesh_req(e_nh, uf.VT_RESPONSE_REQD)
        nh_id = uf.parse_xml_field(nh_resp, "nhr_id")
        print "Got nh id", nh_id
        assert (nh_id.find("1") != -1), "Failed to get nh_id value"
        print "Test encap_nh passed"
        return 0
  
    def test_tunnel_nh(self):
        uf = util_functions()
        vif = uf.create_vif(1, 0, "en0", 0, vt_ipv4("192.168.1.1"), vt_mac("de:ad:be:ef:00:02"), 0)
        uf.send_sandesh_req(vif)
        
        t_nh = uf.create_tunnel_nhv4(1, 1, vt_encap("de ad be ef 00 02 de ad be ef 00 01 08 00"), 0, vt_ipv4("1.1.1.1"), vt_ipv4("1.1.1.2"), vtconst.NH_FLAG_VALID | vtconst.NH_FLAG_TUNNEL_VXLAN, family=socket.AF_INET)
        uf.send_sandesh_req(t_nh)
        t_nh.h_op = vtconst.SANDESH_OPER_GET
        nh_resp = uf.send_sandesh_req(t_nh, uf.VT_RESPONSE_REQD)
        nh_tun_sip = uf.parse_xml_field(nh_resp, "nhr_tun_sip")
        assert (nh_tun_sip.find(str(vt_ipv4("1.1.1.1"))) != -1), "Failed to get nh tun sip"

        print "Test tunnel_nh passed"
        return 0

    def test_rt(self):
        uf  = util_functions()
        vif = uf.create_vif(1, 0, "tap_1", 0, vt_ipv4("192.168.1.1"), vt_mac("de:ad:be:ef:00:02"), 0)
        uf.send_sandesh_req(vif)
     
        e_nh = uf.create_encap_nh(1, 1, vt_encap("de ad be ef 00 02 de ad be ef 00 01 08 00"), 0, socket.AF_BRIDGE, 2)
        uf.send_sandesh_req(e_nh)

        e_nh = uf.create_encap_nh(2, 1, vt_encap("de ad be ef 00 02 de ad be ef 00 01 08 00"), 0, socket.AF_INET, 2)
        uf.send_sandesh_req(e_nh)

        b_rt = uf.create_bridge_rt(0, 1, vt_mac("de:ad:be:ef:00:02"), 0, 0)
        uf.send_sandesh_req(b_rt)

        i_rt = uf.create_inet_rt(0, 2, vt_ipv4_bytes("192.168.1.1"), 32, 0, 0)
        uf.send_sandesh_req(i_rt)

        b_rt.h_op = vtconst.SANDESH_OPER_GET
        b_rt.rtr_nh_id = 0
        b_rt.rtr_index = -1
        rt_resp = uf.send_sandesh_req(b_rt, uf.VT_RESPONSE_REQD)
        nh_id = uf.parse_xml_field(rt_resp, "rtr_nh_id")
        assert (nh_id.find("1") != -1), "Failed to get nh for bridge rt"

        i_rt.h_op = vtconst.SANDESH_OPER_GET
        rt_resp = uf.send_sandesh_req(i_rt, uf.VT_RESPONSE_REQD)
        nh_id = uf.parse_xml_field(rt_resp, "rtr_nh_id")
        assert (nh_id.find("2") != -1), "Failed to get nh for inet rt"
        print "Test rt passed"
        return 0

    def test_flow(self):
        uf = util_functions()
        i_fl = uf.create_inet_flow(-1, 0,  vt_ipv4("1.1.1.1"), vt_ipv4("2.2.2.2"), socket.AF_INET, vtconst.VR_FLOW_ACTION_FORWARD, 17, 100, 1000, -1, vtconst.VR_FLOW_FLAG_ACTIVE, 0, 0)
    
        resp = uf.send_sandesh_req(i_fl, uf.VT_RESPONSE_REQD)
        flow_idx = uf.parse_xml_field(resp, "fresp_index")
        assert (int(flow_idx) > 0), "Failed to add flow"
        print "Test flow passed" 
