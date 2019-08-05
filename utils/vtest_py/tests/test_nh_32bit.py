#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
from vtest_lib import *

# tc to add, del nh with nhid > 65k
def test1_nh32(vrouter_test_fixture):

    vt = vtest("test1_nh32")

    # Add a Vif interface
    vif = vt.get_default_vif_obj(1, "tap1", vtconst.SANDESH_OPER_ADD, \
                             [0xde, 0xad, 0xbe, 0xef, 0x72, 0x32], 16777226)
    #vif.vifr_nh_id = 494949
    vif.vifr_nh_id = 4949
    vt.send_sandesh_req(vif)
 
    # Query the vif back
    vif_get = vt.get_default_vif_obj(1, "tap1")
    resp = vt.send_sandesh_req(vif_get, vt.VT_RESPONSE_REQD)
    vif_nh_id = vt.parse_xml_field(resp, "vifr_nh_id")
    #assert(vif_nh_id.find("494949") != -1), "Vif NH id mismatch"
    assert(vif_nh_id.find("4949") != -1), "Vif NH id mismatch"

    # Add a NH
    #nh = vt.get_default_nh_obj(490496, vtconst.NH_TYPE_ENCAP, \
    #                           vtconst.AF_BRIDGE, vtconst.SANDESH_OPER_ADD)
    nh = vt.get_default_nh_obj(4904, vtconst.NH_TYPE_ENCAP, \
                               vtconst.AF_BRIDGE, vtconst.SANDESH_OPER_ADD)
    nh.nhr_encap_oif_id = 1
    nh.nhr_encap = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, \
                    0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x08, 0x00 ]   
    vt.send_sandesh_req(nh)
   
    # Get the same NH back
    #nh_get = vt.get_default_nh_obj(490496, vtconst.NH_TYPE_ENCAP, \
    #                               vtconst.AF_BRIDGE)
    nh_get = vt.get_default_nh_obj(4904, vtconst.NH_TYPE_ENCAP, \
                                   vtconst.AF_BRIDGE)
    resp = vt.send_sandesh_req(nh_get, vt.VT_RESPONSE_REQD)
    nh_id = vt.parse_xml_field(resp, "nhr_id")
    #assert(nh_id.find("490496") != -1), "NH id mismatch"
    assert(nh_id.find("4904") != -1), "NH id mismatch"
    nh_family = vt.parse_xml_field(resp, "nhr_family")
    assert(nh_family.find(str(int(vtconst.AF_BRIDGE))) != -1), "NH family mismatch"
    nh_type = vt.parse_xml_field(resp, "nhr_type")
    assert(nh_type.find(str(int(vtconst.NH_TYPE_ENCAP))) != -1), "NH type mismatch"

    # Delete the NH now
    #nh_del = vt.get_default_nh_obj(490496, vtconst.NH_TYPE_ENCAP, \
    #                               vtconst.AF_BRIDGE)
    nh_del = vt.get_default_nh_obj(4904, vtconst.NH_TYPE_ENCAP, \
                                   vtconst.AF_BRIDGE)
    nh_del.h_op = vtconst.SANDESH_OPER_DEL
    vt.send_sandesh_req(nh_del)

    return 0


# tc to add, del flow with nhid > 65k
def test2_nh32(vrouter_test_fixture):

    vt = vtest("test2_nh32")

    # Add vif - 10.1.1.1
    vif = vt.get_default_vif_obj(1, "tap1", vtconst.SANDESH_OPER_ADD, \
                              [0xde, 0xad, 0xbe, 0xef, 0x72, 0x32], 16777226)
    #vif.vifr_nh_id = 494949
    vif.vifr_nh_id = 4949
    vt.send_sandesh_req(vif)

    # Add 2nd vif - 10.1.1.2
    vif = vt.get_default_vif_obj(2, "tap2", vtconst.SANDESH_OPER_ADD, \
                              [0xde, 0xad, 0xbe, 0xef, 0x02, 0x02], 33554442)
    #vif.vifr_nh_id = 474747
    vif.vifr_nh_id = 4747
    vt.send_sandesh_req(vif)

    # Add NH
    #nh = vt.get_default_nh_obj(474747, vtconst.NH_TYPE_ENCAP, \
    #                        vtconst.AF_BRIDGE, vtconst.SANDESH_OPER_ADD)
    nh = vt.get_default_nh_obj(4747, vtconst.NH_TYPE_ENCAP, \
                            vtconst.AF_BRIDGE, vtconst.SANDESH_OPER_ADD)
    nh.nhr_encap_oif_id = 2
    nh.nhr_encap = [0xde, 0xad, 0xbe, 0xef, 0x02, 0x02, \
                    0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x08, 0x00 ]   
    vt.send_sandesh_req(nh)
  
    # Add route which points to the NH
    #rt = vt.get_default_rt_obj(vtconst.AF_BRIDGE, 0, None, None, \
    #                        [0xde, 0xad, 0xbe, 0xef, 0x02, 0x02], 474747, \
    #                        vtconst.SANDESH_OPER_ADD)
    rt = vt.get_default_rt_obj(vtconst.AF_BRIDGE, 0, None, None, \
                            [0xde, 0xad, 0xbe, 0xef, 0x02, 0x02], 4747, \
                            vtconst.SANDESH_OPER_ADD)
    vt.send_sandesh_req(rt)

    # Add flow
    flow = vt.get_default_flow_obj([16843009, 0] , [33686018, 0], \
                                vtconst.AF_INET, 17, 31, 31, \
                                vtconst.FLOW_OPER_SET)
    flow.fr_index = -1
    flow.fr_action = 2
    #flow.fr_src_nh_index = 494949
    flow.fr_src_nh_index = 4949
    #flow.fr_flow_nh_id = 594949
    flow.fr_flow_nh_id = 5949
    vt.send_sandesh_req(flow)

    # Delete the flow
    #flow.fr_op = vtconst.FLOW_OPER_SET
    #flow.fr_flags = 0
    #flow.fr_gen_id = 1
    #flow.fr_index = 351928  # this is based on flow key
    #vt.send_sandesh_req(flow)

    return 0

