#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
from vtest_lib import *

def get_vif_obj(idx, name, op=sandeshenum.SANDESH_OPER_GET, mac=[], ip=0):
    vif_obj = vr_interface_req()
    vif_obj.h_op = op
    vif_obj.vifr_type = sandeshenum.SANDESH_VIF_TYPE_VIRTUAL
    vif_obj.vifr_idx = idx
    vif_obj.vifr_name = name
    vif_obj.vifr_transport = sandeshenum.SANDESH_VIF_TRANSPORT_PMD
    vif_obj.vifr_vrf = 0
    vif_obj.vifr_mac = mac
    vif_obj.vifr_mtu = 1514
    vif_obj.vifr_ip = ip
    return vif_obj


def get_nh_obj(id, type, family, op=sandeshenum.SANDESH_OPER_GET):
    nh_obj = vr_nexthop_req()
    nh_obj.h_op = op
    nh_obj.nhr_id = id
    nh_obj.nhr_family = family
    nh_obj.nhr_type = type
    nh_obj.nhr_vrf = 0
    nh_obj.nhr_flags = 1
    return nh_obj


def get_rt_obj(family, vrf, prefix=None, prefix_len=None, mac=None, nh_id=None, \
               op=sandeshenum.SANDESH_OPER_GET):
    rt_obj = vr_route_req()
    rt_obj.h_op = op
    rt_obj.rtr_family = family
    rt_obj.rtr_vrf_id = vrf
    rt_obj.rtr_mac = mac
    rt_obj.rtr_prefix = prefix
    rt_obj.rtr_prefix_len = prefix_len
    rt_obj.rtr_nh_id = nh_id
    return rt_obj

def get_flow_obj(src_ip, dst_ip, family, proto, sport, dport, \
                 op=sandeshenum.SANDESH_FLOW_OPER_TABLE_GET):
    flow_obj = vr_flow_req()
    flow_obj.fr_op = op
    flow_obj.fr_flow_sip_l = src_ip[0]
    flow_obj.fr_flow_sip_h = src_ip[1]
    flow_obj.fr_flow_dip_l = dst_ip[0]
    flow_obj.fr_flow_dip_h = dst_ip[1]
    flow_obj.fr_family = family
    flow_obj.fr_flow_proto = proto
    flow_obj.fr_flow_sport = sport
    flow_obj.fr_flow_dport = dport
    flow_obj.fr_flags = 1
    return flow_obj
    

# tc to add, del nh with nhid > 65k
def test1_nh32(vrouter_test_fixture):

    vt = vtest("test1_nh32")

    # Add a Vif interface
    vif = get_vif_obj(1, "1", sandeshenum.SANDESH_OPER_ADD, \
                      [0xde, 0xad, 0xbe, 0xef, 0x72, 0x32], 16777226)
    vif.vifr_nh_id = 494949
    vt.send_sandesh_req(vif)
 
    # Query the vif back
    vif_get = get_vif_obj(1, "1")
    resp = vt.send_sandesh_req(vif_get, vt.VT_RESPONSE_REQD)
    vif_nh_id = vt.parse_xml_field(resp, "vifr_nh_id")
    assert(vif_nh_id.find("494949") != -1), "Vif NH id mismatch"

    # Add a NH
    nh = get_nh_obj(490496, sandeshenum.SANDESH_NH_TYPE_ENCAP, \
                    sandeshenum.SANDESH_AF_BRIDGE, 
                    sandeshenum.SANDESH_OPER_ADD)
    nh.nhr_encap_oif_id = 1
    nh.nhr_encap = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, \
                    0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x08, 0x00 ]   
    vt.send_sandesh_req(nh)
   
    # Get the same NH back
    nh_get = get_nh_obj(490496, sandeshenum.SANDESH_NH_TYPE_ENCAP, \
                        sandeshenum.SANDESH_AF_BRIDGE)
    resp = vt.send_sandesh_req(nh_get, vt.VT_RESPONSE_REQD)
    nh_id = vt.parse_xml_field(resp, "nhr_id")
    assert(nh_id.find("490496") != -1), "NH id mismatch"
    nh_family = vt.parse_xml_field(resp, "nhr_family")
    assert(nh_family.find(str(int(sandeshenum.SANDESH_AF_BRIDGE))) != -1), "NH family mismatch"
    nh_type = vt.parse_xml_field(resp, "nhr_type")
    assert(nh_type.find(str(int(sandeshenum.SANDESH_NH_TYPE_ENCAP))) != -1), "NH type mismatch"

    # Delete the NH now
    nh_del = get_nh_obj(490496, sandeshenum.SANDESH_NH_TYPE_ENCAP, \
                        sandeshenum.SANDESH_AF_BRIDGE)
    nh_del.h_op = sandeshenum.SANDESH_OPER_DEL
    vt.send_sandesh_req(nh_del)

    return 0


# tc to add, del flow with nhid > 65k
def test2_nh32(vrouter_test_fixture):

    vt = vtest("test2_nh32")

    # Add vif - 10.1.1.1
    vif = get_vif_obj(1, "1", sandeshenum.SANDESH_OPER_ADD, \
                      [0xde, 0xad, 0xbe, 0xef, 0x72, 0x32], 16777226)
    vif.vifr_nh_id = 494949
    vt.send_sandesh_req(vif)

    # Add 2nd vif - 10.1.1.2
    vif = get_vif_obj(2, "2", sandeshenum.SANDESH_OPER_ADD, \
                      [0xde, 0xad, 0xbe, 0xef, 0x02, 0x02], 33554442)
    vif.vifr_nh_id = 474747
    vt.send_sandesh_req(vif)

    # Add NH
    nh = get_nh_obj(474747, sandeshenum.SANDESH_NH_TYPE_ENCAP, \
                    sandeshenum.SANDESH_AF_BRIDGE, 
                    sandeshenum.SANDESH_OPER_ADD)
    nh.nhr_encap_oif_id = 2
    nh.nhr_encap = [0xde, 0xad, 0xbe, 0xef, 0x02, 0x02, \
                    0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x08, 0x00 ]   
    vt.send_sandesh_req(nh)
  
    # Add route which points to the NH
    rt = get_rt_obj(sandeshenum.SANDESH_AF_BRIDGE, 0, None, None, \
                    [0xde, 0xad, 0xbe, 0xef, 0x02, 0x02], 474747, \
                    sandeshenum.SANDESH_OPER_ADD)
    vt.send_sandesh_req(rt)

    # Add flow
    flow = get_flow_obj([16843009, 0] , [33686018, 0], \
                        sandeshenum.SANDESH_AF_INET, 17, 31, 31, \
                        sandeshenum.SANDESH_FLOW_OPER_SET)
    flow.fr_index = -1
    flow.fr_action = 2
    flow.fr_src_nh_index = 494949
    flow.fr_flow_nh_id = 594949
    vt.send_sandesh_req(flow)

    # Delete the flow
    flow.fr_op = sandeshenum.SANDESH_FLOW_OPER_SET
    flow.fr_flags = 0
    flow.fr_gen_id = 1
    flow.fr_index = 351928  # this is based on flow key
    vt.send_sandesh_req(flow)

    return 0

