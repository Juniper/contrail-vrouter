#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')

from vtest_lib import *
import vtconst

# tc to add, del nh with nhid > 65k
def test1_nh32(vrouter_test_fixture):

    vt = vtest("test1_nh32")

    # Add a Vif interface
    vif = VIF(1, "tap_1", vt_ipv4("1.1.1.10"), vt_mac("de:ad:be:ef:00:02"))
    vif.vifr_ip6_u = 72340172838076673
    vif.vifr_ip6_l = 18374403900871474942
    vif.vifr_nh_id = 494949
    vt.send_sandesh_req(vif)
 
    # Query the vif back
    vif_get = VIF(1, "tap_1", vt_ipv4("1.1.1.10"), vt_mac("fe:ad:be:ef:00:02"))
    vif_get.h_op = vtconst.SANDESH_OPER_GET
    resp = vt.send_sandesh_req(vif_get, vt.VT_RESPONSE_REQD)
    vif_nh_id = vt.parse_xml_field(resp, "vifr_nh_id")
    assert(vif_nh_id.find("494949") != -1), "Vif NH id mismatch"

    # Add a NH
    encap_nh = ENCAP_NH(490496, vtconst.AF_BRIDGE, 1, 
                        [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, \
                         0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x08, 0x00 ])
    vt.send_sandesh_req(encap_nh)
   
    # Get the same NH back
    nh_get = ENCAP_NH(490496, vtconst.AF_BRIDGE, 1, [])
    nh_get.h_op = vtconst.SANDESH_OPER_GET
    resp = vt.send_sandesh_req(nh_get, vt.VT_RESPONSE_REQD)
    nh_id = vt.parse_xml_field(resp, "nhr_id")
    assert(nh_id.find("490496") != -1), "NH id mismatch"
    nh_family = vt.parse_xml_field(resp, "nhr_family")
    assert(nh_family.find(str(int(vtconst.AF_BRIDGE))) != -1), "NH family mismatch"
    nh_type = vt.parse_xml_field(resp, "nhr_type")
    assert(nh_type.find(str(int(vtconst.NH_TYPE_ENCAP))) != -1), "NH type mismatch"

    # Delete the NH now
    nh_del = ENCAP_NH(490496, vtconst.AF_BRIDGE, 1, [])
    nh_del.h_op = vtconst.SANDESH_OPER_DEL
    vt.send_sandesh_req(nh_del)

    return 0


# tc to add, del flow with nhid > 65k
def test2_nh32(vrouter_test_fixture):

    vt = vtest("test2_nh32")

    # Add vif - 10.1.1.1
    vif = VIF(1, "tap_1", vt_ipv4("10.1.1.1"), vt_mac("de:ad:be:ef:00:02"))
    vif.vifr_nh_id = 494949
    vt.send_sandesh_req(vif)

    # Add 2nd vif - 10.1.1.2
    vif = VIF(2, "tap_2", vt_ipv4("10.1.1.2"), vt_mac("ed:da:eb:fe:00:03"))
    vif.vifr_nh_id = 474747
    vt.send_sandesh_req(vif)

    # Add NH
    encap_nh = ENCAP_NH(474747, vtconst.AF_BRIDGE, 2, 
                        [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, \
                         0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x08, 0x00 ])
    vt.send_sandesh_req(encap_nh)
  
    # Add route which points to the NH
    rt = BRIDGE_RT(0, [0xde, 0xad, 0xbe, 0xef, 0x02, 0x02], 474747)
    vt.send_sandesh_req(rt)

    # Add flow
    flow = INET_FLOW(-1, 16843009, 33686018, 17, 31, 31)
    flow.fr_action = 2
    flow.fr_src_nh_index = 494949
    flow.fr_flow_nh_id = 594949
    vt.send_sandesh_req(flow)

    # Delete the flow
    flow.fr_op = vtconst.FLOW_SET
    flow.fr_flags = 0
    flow.fr_gen_id = 1
    flow.fr_index = 361744  # this is based on flow key
    vt.send_sandesh_req(flow)

    return 0

