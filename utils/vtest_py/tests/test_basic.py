#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')

from vtest_lib import *
import vtconst

# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test
def test_vif(vrouter_test_fixture):

    vt = vtest("test_vif")

    # add the vif
    vmi = VIF(1, "tap_1", vt_ipv4("1.1.1.10"), vt_mac("de:ad:be:ef:00:02"))
    vt.send_sandesh_req(vmi)

    # query the vif and see if it really got added
    vmi = VIF(1, "tap_1", 0, [])
    vmi.h_op = vtconst.SANDESH_OPER_GET
    vif_resp_file = vt.send_sandesh_req(vmi, vt.VT_RESPONSE_REQD)

    # parse the fields and validate the response
    vif_name = vt.parse_xml_field(vif_resp_file, "vifr_name")
    print "Got vif name ", vif_name
    assert (vif_name.find("tap_1") != -1), "Failed to get vif name"
    vif_mtu = vt.parse_xml_field(vif_resp_file, "vifr_mtu")
    print "Got vif mtu ", vif_mtu
    assert (vif_mtu.find("1514") != -1), "Failed to get mtu value"
    print "Test vif passed"
    return 0

def test_encap_nh(vrouter_test_fixture):
    
    vt = vtest("test_encap_nh")

    vmi = VIF(1, "tap_1", vt_ipv4("1.1.1.10"), vt_mac("de:ad:be:ef:00:02"))
    vt.send_sandesh_req(vmi)

    nh = ENCAP_NH(1, vtconst.AF_INET, 1, vt_encap("de ad be ef 00 02 de ad be ef 00 01 08 00"))
    vt.send_sandesh_req(nh)

    nh.h_op = vtconst.SANDESH_OPER_GET
    nh_resp = vt.send_sandesh_req(nh, vt.VT_RESPONSE_REQD)
    nh_id = vt.parse_xml_field(nh_resp, "nhr_id")
    print "Got nh id", nh_id
    assert (nh_id.find("1") != -1), "Failed to get nh_id value"
    print "Test encap_nh passed"
    return 0

def test_tunnel_nh(vrouter_test_fixture):

    vt = vtest("test_tunnel_nh")

    vmi = VIF(1, "en0", vt_ipv4("192.168.1.1"), vt_mac("de:ad:be:ef:00:02"))
    vmi.vifr_type = vtconst.VIF_TYPE_PHYSICAL
    vt.send_sandesh_req(vmi)

    nh = TUNNEL_NHV4(1, vt_ipv4("1.1.1.1"), vt_ipv4("1.1.1.2"), \
                     1, vt_encap("de ad be ef 00 02 de ad be ef 00 01 08 00"))
    nh.nhr_flags |= vtconst.NH_FLAG_TUNNEL_VXLAN
    vt.send_sandesh_req(nh)

    nh.h_op = vtconst.SANDESH_OPER_GET
    nh_resp = vt.send_sandesh_req(nh, vt.VT_RESPONSE_REQD)
    nh_tun_sip = vt.parse_xml_field(nh_resp, "nhr_tun_sip")
    assert (nh_tun_sip.find(str(vt_ipv4("1.1.1.1"))) != -1), "Failed to get nh tun sip"

    # Temp to simulate failure
    assert (0), "Temp failure"

    print "Test tunnel_nh passed"
    return 0


def test_rt(vrouter_test_fixture):

    vt = vtest("test_rt")

    vmi = VIF(1, "tap1", vt_ipv4("192.168.1.1"), vt_mac("de:ad:be:ef:00:02"))
    vt.send_sandesh_req(vmi)

    nh = ENCAP_NH(1, vtconst.AF_BRIDGE, 1, vt_encap("de ad be ef 00 02 de ad be ef 00 01 08 00"))
    vt.send_sandesh_req(nh)

    nh = ENCAP_NH(2, vtconst.AF_INET, 1, vt_encap("de ad be ef 00 02 de ad be ef 00 01 08 00"))
    vt.send_sandesh_req(nh)

    bridge_rt = BRIDGE_RT(0, vt_mac("de:ad:be:ef:00:02"), 1)
    vt.send_sandesh_req(bridge_rt)
    
    inet_rt = INET_RT(0, vt_ipv4_bytes("192.168.1.1"), 32, 2)
    vt.send_sandesh_req(inet_rt)

    # Query the routes back
    bridge_rt.h_op = vtconst.SANDESH_OPER_GET
    bridge_rt.rtr_nh_id = 0
    bridge_rt.rtr_index = -1
    rt_resp = vt.send_sandesh_req(bridge_rt, vt.VT_RESPONSE_REQD)
    nh_id = vt.parse_xml_field(rt_resp, "rtr_nh_id")
    assert (nh_id.find("1") != -1), "Failed to get nh for bridge rt"

    inet_rt.h_op = vtconst.SANDESH_OPER_GET
    rt_resp = vt.send_sandesh_req(inet_rt, vt.VT_RESPONSE_REQD)
    nh_id = vt.parse_xml_field(rt_resp, "rtr_nh_id")
    assert (nh_id.find("2") != -1), "Failed to get nh for inet rt"
    print "Test rt passed"
    return 0

def test_flow(vrouter_test_fixture):
    vt = vtest("test_flow")

    flow = INET_FLOW(-1, vt_ipv4("1.1.1.1"), vt_ipv4("2.2.2.2"), 17, 100, 1000)
    resp = vt.send_sandesh_req(flow, vt.VT_RESPONSE_REQD)
    flow_idx = vt.parse_xml_field(resp, "fresp_index")
    assert (int(flow_idx) > 0), "Failed to add flow"
    print "Test flow passed"
    return 0
