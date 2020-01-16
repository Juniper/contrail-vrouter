#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')

from vtest_lib import *
import vtconst

# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test

#
# Test case:
# Do the following RT operations
# Addr = 10.60.7.0 plen = 25 vrf = 4 operation = ADD/CHANGE nh_idx = 38 label = 410760
# Addr = 10.60.0.0 plen = 23 vrf = 4 operation = ADD/CHANGE nh_idx = 38 label = 410760
# Addr = 10.60.7.128 plen = 25 vrf = 4 operation = ADD/CHANGE nh_idx = 38 label = 410760
# Addr = 10.60.0.0 plen = 20 vrf = 4 operation = ADD/CHANGE nh_idx = 2 label = 609700
# Addr = 10.60.0.0 plen = 20 vrf = 4 operation = DELETE nh_idx = 2
# After the above operations, rt get of 10.60.7.3/32 should return nh = 38 and label = 410760.
# Similarly rt get of 10.60.7.144/32 should return nh = 38 and label = 410760.
#
def test_cem_11421(vrouter_test_fixture):

    vt = vtest("test_cem_11421")

    vmi = VIF(1, "tap1", vt_ipv4("192.168.1.3"), vt_mac("de:ad:be:ef:00:02"))
    vt.send_sandesh_req(vmi)

    nh = ENCAP_NH(38, vtconst.AF_INET, 1, vt_encap("de ad be ef 00 02 de ad be ef 00 01 08 00"))
    vt.send_sandesh_req(nh)

    vmi = VIF(2, "tap2", vt_ipv4("192.168.1.4"), vt_mac("de:ad:be:ef:00:04"))
    vt.send_sandesh_req(vmi)

    nh = ENCAP_NH(2, vtconst.AF_INET, 2, vt_encap("de ad be ef 00 04 de ad be ef 00 01 08 00"))
    vt.send_sandesh_req(nh)

    # Do the route operations
    inet_rt = INET_RT(4, vt_ipv4_bytes("10.60.7.0"), 25, 38)
    inet_rt.rtr_label_flags = vtconst.VR_RT_LABEL_VALID_FLAG | vtconst.VR_RT_ARP_PROXY_FLAG
    inet_rt.rtr_label = 410760
    vt.send_sandesh_req(inet_rt)

    inet_rt = INET_RT(4, vt_ipv4_bytes("10.60.0.0"), 23, 38)
    inet_rt.rtr_label_flags = vtconst.VR_RT_LABEL_VALID_FLAG | vtconst.VR_RT_ARP_PROXY_FLAG
    inet_rt.rtr_label = 410760
    vt.send_sandesh_req(inet_rt)

    inet_rt = INET_RT(4, vt_ipv4_bytes("10.60.7.128"), 25, 38)
    inet_rt.rtr_label_flags = vtconst.VR_RT_LABEL_VALID_FLAG | vtconst.VR_RT_ARP_PROXY_FLAG
    inet_rt.rtr_label = 410760
    vt.send_sandesh_req(inet_rt)

    inet_rt = INET_RT(4, vt_ipv4_bytes("10.60.0.0"), 20, 2)
    inet_rt.rtr_label_flags = vtconst.VR_RT_LABEL_VALID_FLAG | vtconst.VR_RT_ARP_PROXY_FLAG
    inet_rt.rtr_label = 609700
    vt.send_sandesh_req(inet_rt)

    inet_rt = INET_RT(4, vt_ipv4_bytes("10.60.0.0"), 20, 2)
    inet_rt.rtr_label_flags = vtconst.VR_RT_LABEL_VALID_FLAG | vtconst.VR_RT_ARP_PROXY_FLAG
    inet_rt.h_op = vtconst.SANDESH_OPER_DEL
    vt.send_sandesh_req(inet_rt)

    # Query the routes back
    inet_rt = INET_RT(4, vt_ipv4_bytes("10.60.7.3"), 32, 0)
    inet_rt.h_op = vtconst.SANDESH_OPER_GET
    rt_resp = vt.send_sandesh_req(inet_rt, vt.VT_RESPONSE_REQD)
    nh_id = vt.parse_xml_field(rt_resp, "rtr_nh_id")
    assert (nh_id.find("38") != -1), "Failed to get nh for inet rt"

    inet_rt = INET_RT(4, vt_ipv4_bytes("10.60.7.144"), 32, 0)
    inet_rt.h_op = vtconst.SANDESH_OPER_GET
    rt_resp = vt.send_sandesh_req(inet_rt, vt.VT_RESPONSE_REQD)
    nh_id = vt.parse_xml_field(rt_resp, "rtr_nh_id")
    assert (nh_id.find("38") != -1), "Failed to get nh for inet rt"

    print "Test CEM-11421 passed"
    return 0

