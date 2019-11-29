#!/usr/bin/python

import os
import sys
import ipaddress
import socket
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
import vtconst
from vtest_lib import *

@pytest.mark.skip(reason="failing because of vr_uvh_cl_timer_setup() not setup")
def test_hbs_vm_to_vm_inter_vn(vrouter_test_fixture):

    vt = vtest("test_hbs_vm_to_vm_inter_vn")

   # Add hbs-l vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 5
    vif.vifr_name = "tap1589a2b3-22"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_flags = vtconst.VIF_FLAG_POLICY_ENABLED | vtconst.VIF_FLAG_HBS_LEFT
    vif.vifr_vrf = 3
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("100.100.100.4")

    vt.send_sandesh_req(vif)

    # Add hbs-r vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 6
    vif.vifr_name = "tap8b05a86b-36"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_flags = vtconst.VIF_FLAG_POLICY_ENABLED | vtconst.VIF_FLAG_HBS_RIGHT
    vif.vifr_vrf = 4
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("200.200.200.4")

    vt.send_sandesh_req(vif)

    # Add tenant vif3
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 3
    vif.vifr_mcast_vrf = 3
    vif.vifr_name = "tap88670c2e-11"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 3
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("1.1.1.4")
    vif.vifr_nh_id = 23
    vif.vifr_flags = vtconst.VIF_FLAG_POLICY_ENABLED | vtconst.VIF_FLAG_DHCP_ENABLED

    vt.send_sandesh_req(vif)

    # Add tenant vif4
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 4
    vif.vifr_mcast_vrf = 4
    vif.vifr_name = "tape703ea67-f1"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 4
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("2.2.2.4")
    vif.vifr_nh_id = 28
    vif.vifr_flags = vtconst.VIF_FLAG_POLICY_ENABLED | vtconst.VIF_FLAG_DHCP_ENABLED

    vt.send_sandesh_req(vif)

    # Add vif3 Nexthop (inet)
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_TYPE_ENCAP
    nh.nhr_id = 23
    nh.nhr_encap_oif_id = 3
    nh.nhr_encap = vt_encap("02 88 67 0c 2e 11 00 00 5e 00 01 00 08 00")
    nh.nhr_vrf = 3
    nh.nhr_flags = vtconst.NH_FLAG_VALID | \
                   vtconst.NH_FLAG_POLICY_ENABLED |\
                   vtconst.NH_FLAG_ETREE_ROOT
    nh.nhr_family = socket.AF_INET

    vt.send_sandesh_req(nh)

    # Add vif4 Nexthop (inet)
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_TYPE_ENCAP
    nh.nhr_id = 28
    nh.nhr_encap_oif_id = 4
    nh.nhr_encap = vt_encap("02 e7 03 ea 67 f1 00 00 5e 00 01 00 08 00")
    nh.nhr_vrf = 4
    nh.nhr_flags = vtconst.NH_FLAG_VALID | \
                   vtconst.NH_FLAG_POLICY_ENABLED |\
                   vtconst.NH_FLAG_ETREE_ROOT
    nh.nhr_family = socket.AF_INET

    vt.send_sandesh_req(nh)

    # Add overlay L2 Receive NH
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_TYPE_L2_RCV
    nh.nhr_id = 3
    nh.nhr_vrf = 0
    nh.nhr_family = socket.AF_INET
    nh.nhr_flags = vtconst.NH_FLAG_VALID |\
                   vtconst.NH_FLAG_ETREE_ROOT

    vt.send_sandesh_req(nh)

    # Add vif3 bridge Route with agent MAC
    route = vr_route_req()
    route.h_op = vtconst.SANDESH_OPER_ADD
    route.rtr_family = vtconst.AF_BRIDGE
    route.rtr_nh_id = 3
    route.rtr_mac = vt_mac("00:00:5e:00:01:00")
    route.rtr_vrf_id = 3

    vt.send_sandesh_req(route)

    # Add vif4 bridge Route with agent MAC
    route = vr_route_req()
    route.h_op = vtconst.SANDESH_OPER_ADD
    route.rtr_family = vtconst.AF_BRIDGE
    route.rtr_nh_id = 3
    route.rtr_mac = vt_mac("00:00:5e:00:01:00")
    route.rtr_vrf_id = 4

    vt.send_sandesh_req(route)

    # Add vif3 Route (note this is vif4's subnet route)
    route = vr_route_req()
    route.h_op = vtconst.SANDESH_OPER_ADD
    route.rtr_family = socket.AF_INET
    route.rtr_nh_id = 28
    route.rtr_prefix = vt_encap("02 02 02 04")
    route.rtr_prefix_len = 32
    route.rtr_vrf_id = 3
    route.rtr_label_flags = vtconst.VR_RT_ARP_PROXY_FLAG

    vt.send_sandesh_req(route)

    # Add vif4 Route (note this is vif3's subnet route)
    route = vr_route_req()
    route.h_op = vtconst.SANDESH_OPER_ADD
    route.rtr_family = socket.AF_INET
    route.rtr_nh_id = 23
    route.rtr_prefix = vt_encap("01 01 01 04")
    route.rtr_prefix_len = 32
    route.rtr_vrf_id = 4
    route.rtr_label_flags = vtconst.VR_RT_ARP_PROXY_FLAG

    vt.send_sandesh_req(route)

    # Add vif3 Nexthop (bridge)
    # pkt from hbs-r to vif 3 will need a lookup of dst-mac in the bridge table
    # this is because dmac would have been encoded with flow id
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_TYPE_ENCAP
    nh.nhr_id = 27
    nh.nhr_encap_oif_id = 3
    nh.nhr_encap = vt_encap("02 88 67 0c 2e 11 00 00 5e 00 01 00 08 00")
    nh.nhr_vrf = 3
    nh.nhr_flags = vtconst.NH_FLAG_VALID | \
                   vtconst.NH_FLAG_POLICY_ENABLED |\
                   vtconst.NH_FLAG_ETREE_ROOT
    nh.nhr_family = vtconst.AF_BRIDGE

    vt.send_sandesh_req(nh)

    # Add bridge Route
    route = vr_route_req()
    route.h_op = vtconst.SANDESH_OPER_ADD
    route.rtr_family = vtconst.AF_BRIDGE
    route.rtr_nh_id = 27
    route.rtr_mac = vt_mac("02:88:67:0c:2e:11")
    route.rtr_vrf_id = 3

    vt.send_sandesh_req(route)

    #Add forward Flow
    flow = vr_flow_req()
    flow.fr_op = vtconst.FLOW_OPER_SET
    flow.fr_flow_sip_l = vt_ipv4("1.1.1.4")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("2.2.2.4")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = -1
    flow.fr_rindex = -1
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE
    flow.fr_flags1 = vtconst.VR_FLOW_FLAG1_HBS_LEFT
    flow.fr_flow_proto = vtconst.VR_IP_PROTO_ICMP
    flow.fr_flow_sport = socket.htons(1136)
    flow.fr_flow_nh_id = 23
    flow.fr_src_nh_index = 23
    flow.fr_qos_id = -1
    flow.fr_action = vtconst.VR_FLOW_ACTION_FORWARD
    flow.fr_flow_dport = 0
    flow.fr_ecmp_nh_index = -1
    flow.fr_flow_vrf = 3
    flow.rflow_sip_u = 0
    flow.rflow_sip_l = vt_ipv4("2.2.2.4")
    flow.rflow_dip_u = 0
    flow.rflow_dip_l = vt_ipv4("1.1.1.4")
    flow.rflow_nh_id = 28
    flow.rflow_sport = socket.htons(1136)

    resp_file = vt.send_sandesh_req(flow, vt.VT_RESPONSE_REQD)

    fr_indx = vt.parse_xml_field(resp_file, "fresp_index")
    fr_genid = vt.parse_xml_field(resp_file, "fresp_gen_id")

    #Add reverse Flow
    flow = vr_flow_req()
    flow.fr_op = vtconst.FLOW_OPER_SET
    flow.fr_flow_sip_l = vt_ipv4("2.2.2.4")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("1.1.1.4")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = -1
    flow.fr_rindex = int(fr_indx)
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE | vtconst.VR_RFLOW_VALID
    flow.fr_flags1 = vtconst.VR_FLOW_FLAG1_HBS_RIGHT
    flow.fr_flow_proto = vtconst.VR_IP_PROTO_ICMP
    flow.fr_flow_sport = socket.htons(1136)
    flow.fr_flow_nh_id = 28
    flow.fr_src_nh_index = 28
    flow.fr_qos_id = -1
    flow.fr_action = vtconst.VR_FLOW_ACTION_FORWARD
    flow.fr_flow_dport = 0
    flow.fr_ecmp_nh_index = -1
    flow.fr_flow_vrf = 4
    flow.rflow_sip_u = 0
    flow.rflow_sip_l = vt_ipv4("1.1.1.4")
    flow.rflow_dip_u = 0
    flow.rflow_dip_l = vt_ipv4("2.2.2.4")
    flow.rflow_nh_id = 23
    flow.rflow_sport = socket.htons(1136)

    resp_file = vt.send_sandesh_req(flow, vt.VT_RESPONSE_REQD)

    rfr_indx = vt.parse_xml_field(resp_file, "fresp_index")

    # Update forward flow
    flow = vr_flow_req()
    flow.fr_op = vtconst.FLOW_OPER_SET
    flow.fr_flow_sip_l = vt_ipv4("1.1.1.4")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("2.2.2.4")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = int(fr_indx)
    flow.fr_rindex = int(rfr_indx)
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE | vtconst.VR_RFLOW_VALID
    flow.fr_flags1 = vtconst.VR_FLOW_FLAG1_HBS_LEFT
    flow.fr_flow_proto = vtconst.VR_IP_PROTO_ICMP
    flow.fr_flow_sport = socket.htons(1136)
    flow.fr_flow_nh_id = 23
    flow.fr_src_nh_index = 23
    flow.fr_gen_id = int(fr_genid)
    flow.fr_qos_id = -1
    flow.fr_action = vtconst.VR_FLOW_ACTION_FORWARD
    flow.fr_flow_dport = 0
    flow.fr_ecmp_nh_index = -1
    flow.fr_flow_vrf = 3
    flow.rflow_sip_u = 0
    flow.rflow_sip_l = vt_ipv4("2.2.2.4")
    flow.rflow_dip_u = 0
    flow.rflow_dip_l = vt_ipv4("1.1.1.4")
    flow.rflow_nh_id = 28
    flow.rflow_sport = socket.htons(1136)

    resp_file = vt.send_sandesh_req(flow, vt.VT_RESPONSE_REQD)

    fr_indx = vt.parse_xml_field(resp_file, "fresp_index")

    # Add hbs-l and hbs-r in vrf table
    vrf = vr_vrf_req()
    vrf.h_op = vtconst.SANDESH_OPER_ADD
    vrf.vrf_rid = 0
    vrf.vrf_idx = 3
    vrf.vrf_flags = vtconst.VRF_FLAG_VALID |\
                    vtconst.VRF_FLAG_HBS_L_VALID |\
                    vtconst.VRF_FLAG_HBS_R_VALID
    vrf.vrf_hbfl_vif_idx = 5
    vrf.vrf_hbfr_vif_idx = 6

    vt.send_sandesh_req(vrf)

    # Add hbs-l and hbs-r in vrf table
    vrf = vr_vrf_req()
    vrf.h_op = vtconst.SANDESH_OPER_ADD
    vrf.vrf_rid = 0
    vrf.vrf_idx = 4
    vrf.vrf_flags = vtconst.VRF_FLAG_VALID |\
                    vtconst.VRF_FLAG_HBS_L_VALID |\
                    vtconst.VRF_FLAG_HBS_R_VALID
    vrf.vrf_hbfl_vif_idx = 5
    vrf.vrf_hbfr_vif_idx = 6

    vt.send_sandesh_req(vrf)

    # send ping request from vif3 and receive in hbs-l
    eth = Ether(src='02:88:67:0c:2e:11', dst='00:00:5e:00:01:00', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='icmp', dst='2.2.2.4', src='1.1.1.4')
    icmp = ICMP(type=8, code=0, id=1136)
    pkt = eth/ip/icmp
    pkt.show()

    # send packet
    vt.send_recv_pkt(pkt, "tap88670c2e-11", pkt, "tap1589a2b3-22")

    # send ping request from hbs-r and receive in vif4
    eth = Ether(src='ca:f1:00:00:a9:4c', dst='00:00:5e:00:01:00', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='icmp', dst='2.2.2.4', src='1.1.1.4')
    icmp = ICMP(type=8, code=0, id=1136)
    pkt = eth/ip/icmp
    pkt.show()

    # send packet
    vt.send_recv_pkt(pkt, "tap8b05a86b-36", pkt, "tape703ea67-f1")

    # send ping response from vif4 and receive in hbs-r
    eth = Ether(dst='00:00:5e:00:01:00', src='02:e7:03:ea:67:f1', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='icmp', src='2.2.2.4', dst='1.1.1.4')
    icmp = ICMP(type=0, code=0, id=1136)
    pkt = eth/ip/icmp
    pkt.show()

    # send packet
    vt.send_recv_pkt(pkt, "tape703ea67-f1", pkt, "tap8b05a86b-36")

    # send ping response from hbs-r and receive in vif3
    eth = Ether(src='00:00:5e:00:01:00', dst='c0:d1:00:04:05:8c', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='icmp', src='2.2.2.4', dst='1.1.1.4')
    icmp = ICMP(type=0, code=0, id=1136)
    pkt = eth/ip/icmp
    pkt.show()

    # send packet
    vt.send_recv_pkt(pkt, "tap1589a2b3-22", pkt, "tap88670c2e-11")

    # Check if the ping request was sent at vif3 and received at hbs-l
    # Check if the ping request was sent at hbs-r and received at vif4
    # Check if the ping response was sent at vif4 and received at hbs-r
    # Check if the ping response was sent at hbs-l and received at vif3
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_GET
    vif.vifr_idx = 3
    vif_resp_file = vt.send_sandesh_req(vif, vt.VT_RESPONSE_REQD)
    vif_opackets = vt.parse_xml_field(vif_resp_file, "vifr_opackets")
    assert (vif_opackets.find("1") != -1), "Failed to receive packet"
    vif_ipackets = vt.parse_xml_field(vif_resp_file, "vifr_ipackets")
    assert (vif_ipackets.find("1") != -1), "Failed to send packet"

    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_GET
    vif.vifr_idx = 4
    vif_resp_file = vt.send_sandesh_req(vif, vt.VT_RESPONSE_REQD)
    vif_opackets = vt.parse_xml_field(vif_resp_file, "vifr_opackets")
    assert (vif_opackets.find("1") != -1), "Failed to receive packet"
    vif_ipackets = vt.parse_xml_field(vif_resp_file, "vifr_ipackets")
    assert (vif_ipackets.find("1") != -1), "Failed to send packet"

    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_GET
    vif.vifr_idx = 5
    vif_resp_file = vt.send_sandesh_req(vif, vt.VT_RESPONSE_REQD)
    vif_opackets = vt.parse_xml_field(vif_resp_file, "vifr_opackets")
    assert (vif_opackets.find("1") != -1), "Failed to receive packet"
    vif_ipackets = vt.parse_xml_field(vif_resp_file, "vifr_ipackets")
    assert (vif_ipackets.find("1") != -1), "Failed to send packet"

    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_GET
    vif.vifr_idx = 6
    vif_resp_file = vt.send_sandesh_req(vif, vt.VT_RESPONSE_REQD)
    vif_opackets = vt.parse_xml_field(vif_resp_file, "vifr_opackets")
    assert (vif_opackets.find("1") != -1), "Failed to receive packet"
    vif_ipackets = vt.parse_xml_field(vif_resp_file, "vifr_ipackets")
    assert (vif_ipackets.find("1") != -1), "Failed to send packet"
