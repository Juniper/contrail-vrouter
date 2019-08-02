#!/usr/bin/python

import os
import sys
import ipaddress
import socket
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from vtest_lib import *
import vtconst

def test_hbf_vmi_to_fabric(vrouter_test_fixture):

    vt = vtest("test_hbf_vmi_to_fabric")

    # Add fabric interface
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_PHYSICAL
    vif.vifr_idx = 1
    vif.vifr_name = "1"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 0
    vif.vifr_mac = vt_mac("00:1b:21:bb:f9:48")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("8.0.0.2")

    vt.send_sandesh_req(vif)

   # Add hbf-l vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 3
    vif.vifr_name = "tap1589a2b3-22"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_flags = vtconst.VIF_FLAG_POLICY_ENABLED | vtconst.VIF_FLAG_HBS_LEFT
    vif.vifr_vrf = 3
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("100.100.100.4")

    vt.send_sandesh_req(vif)

    # Add hbf-r vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 4
    vif.vifr_name = "tap8b05a86b-36"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_flags = vtconst.VIF_FLAG_POLICY_ENABLED | vtconst.VIF_FLAG_HBS_RIGHT
    vif.vifr_vrf = 4
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("200.200.200.4")

    vt.send_sandesh_req(vif)

    # Add tenant vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 5
    vif.vifr_name = "tapc2234cd0-55"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 5
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("1.1.1.3")
    vif.vifr_flags = vtconst.VIF_FLAG_POLICY_ENABLED
    vif.vifr_nh_id = 38

    vt.send_sandesh_req(vif)

    # Add vif Nexthop
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_ENCAP
    nh.nhr_id = 38
    nh.nhr_encap_oif_id = 5
    nh.nhr_encap = vt_encap("02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00")
    nh.nhr_vrf = 5
    nh.nhr_flags = vtconst.NH_FLAG_VALID | vtconst.NH_FLAG_POLICY_ENABLED
    nh.nhr_family = socket.AF_INET

    vt.send_sandesh_req(nh)

    # Add tunnel NH
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_TUNNEL
    nh.nhr_id = 21
    nh.nhr_encap_oif_id = 1
    nh.nhr_encap = vt_encap("00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00")
    nh.nhr_tun_sip = vt_ipv4("8.0.0.2")
    nh.nhr_tun_dip = vt_ipv4("8.0.0.3")
    nh.nhr_vrf = 0
    nh.nhr_family = socket.AF_INET
    nh.nhr_flags = vtconst.NH_FLAG_VALID |\
                   vtconst.NH_FLAG_TUNNEL_UDP_MPLS |\
                   vtconst.NH_FLAG_ETREE_ROOT
    vt.send_sandesh_req(nh)

    # Add bridge Route
    route = vr_route_req()
    route.h_op = vtconst.SANDESH_OPER_ADD
    route.rtr_family = vtconst.AF_BRIDGE
    route.rtr_nh_id = 21
    route.rtr_mac = vt_mac("02:e7:03:ea:67:f1")
    route.rtr_label = 27
    route.rtr_vrf_id = 5
    route.rtr_label_flags = vtconst.VR_RT_LABEL_VALID_FLAG |\
                            vtconst.VR_RT_ARP_PROXY_FLAG |\
                            vtconst.VR_BE_FLOOD_DHCP_FLAG

    vt.send_sandesh_req(route)

    #Add forward Flow
    flow = vr_flow_req()
    flow.fr_op = vtconst.FLOW_SET
    flow.fr_flow_sip_l = vt_ipv4("1.0.0.3")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("1.0.0.5")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = -1
    flow.fr_rindex = -1
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE
    flow.fr_flags1 = vtconst.VR_FLOW_FLAG1_HBS_LEFT
    flow.fr_flow_proto = vtconst.VR_IP_PROTO_ICMP
    flow.fr_flow_sport = socket.htons(4145)
    flow.fr_flow_nh_id = 38
    flow.fr_src_nh_index = 38
    flow.fr_qos_id = -1
    flow.fr_action = vtconst.VR_FLOW_ACTION_FORWARD
    flow.fr_flow_dport = 0
    flow.fr_ecmp_nh_index = -1
    flow.fr_flow_vrf = 5
    flow.rflow_sip_u = 0
    flow.rflow_sip_l = vt_ipv4("1.0.0.5")
    flow.rflow_dip_u = 0
    flow.rflow_dip_l = vt_ipv4("1.0.0.3")
    flow.rflow_nh_id = 21
    flow.rflow_sport = socket.htons(4145)

    resp_file = vt.send_sandesh_req(flow, vt.VT_RESPONSE_REQD)

    fr_indx = vt.parse_xml_field(resp_file, "fresp_index")
    fr_genid = vt.parse_xml_field(resp_file, "fresp_gen_id")

    #Add reverse Flow
    flow = vr_flow_req()
    flow.fr_op = vtconst.FLOW_SET
    flow.fr_flow_sip_l = vt_ipv4("1.0.0.5")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("1.0.0.3")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = -1
    flow.fr_rindex = int(fr_indx)
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE | vtconst.VR_RFLOW_VALID
    flow.fr_flags1 = vtconst.VR_FLOW_FLAG1_HBS_RIGHT
    flow.fr_flow_proto = vtconst.VR_IP_PROTO_ICMP
    flow.fr_flow_sport = socket.htons(4145)
    flow.fr_flow_nh_id = 38
    flow.fr_src_nh_index = 21
    flow.fr_qos_id = -1
    flow.fr_action = vtconst.VR_FLOW_ACTION_FORWARD
    flow.fr_flow_dport = 0
    flow.fr_ecmp_nh_index = -1
    flow.fr_flow_vrf = 5
    flow.rflow_sip_u = 0
    flow.rflow_sip_l = vt_ipv4("1.0.0.3")
    flow.rflow_dip_u = 0
    flow.rflow_dip_l = vt_ipv4("1.0.0.5")
    flow.rflow_nh_id = 21
    flow.rflow_sport = socket.htons(4145)

    resp_file = vt.send_sandesh_req(flow, vt.VT_RESPONSE_REQD)

    rfr_indx = vt.parse_xml_field(resp_file, "fresp_index")

    # Update forward flow
    flow = vr_flow_req()
    flow.fr_op = vtconst.FLOW_SET
    flow.fr_flow_sip_l = vt_ipv4("1.0.0.3")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("1.0.0.5")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = int(fr_indx)
    flow.fr_rindex = int(rfr_indx)
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE | vtconst.VR_RFLOW_VALID
    flow.fr_flags1 = vtconst.VR_FLOW_FLAG1_HBS_LEFT
    flow.fr_flow_proto = vtconst.VR_IP_PROTO_ICMP
    flow.fr_flow_sport = socket.htons(4145)
    flow.fr_flow_nh_id = 38
    flow.fr_src_nh_index = 38
    flow.fr_gen_id = int(fr_genid)
    flow.fr_qos_id = -1
    flow.fr_action = vtconst.VR_FLOW_ACTION_FORWARD
    flow.fr_flow_dport = 0
    flow.fr_ecmp_nh_index = -1
    flow.fr_flow_vrf = 5
    flow.rflow_sip_u = 0
    flow.rflow_sip_l = vt_ipv4("1.0.0.5")
    flow.rflow_dip_u = 0
    flow.rflow_dip_l = vt_ipv4("1.0.0.3")
    flow.rflow_nh_id = 21
    flow.rflow_sport = socket.htons(4145)

    resp_file = vt.send_sandesh_req(flow, vt.VT_RESPONSE_REQD)

    fr_indx = vt.parse_xml_field(resp_file, "fresp_index")



    # Add hbf-l and hbf-r in vrf table
    vrf = vr_vrf_req()
    vrf.h_op = vtconst.SANDESH_OPER_ADD
    vrf.vrf_rid = 0
    vrf.vrf_idx = 5
    vrf.vrf_flags = vtconst.VRF_FLAG_VALID |\
                    vtconst.VRF_FLAG_HBF_L_VALID |\
                    vtconst.VRF_FLAG_HBF_R_VALID
    vrf.vrf_hbfl_vif_idx = 3
    vrf.vrf_hbfr_vif_idx = 4

    vt.send_sandesh_req(vrf)

    eth = Ether(dst='02:e7:03:ea:67:f1', src='02:c2:23:4c:d0:55', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='icmp', src='1.0.0.3', dst='1.0.0.5')
    icmp = ICMP(type=8, code=0, id=4145)
    pkt = eth/ip/icmp
    pkt.show()

    # Make sure the packet comes goes to hbf-l (tap1589a2b3-22)
    vt.send_recv_pkt(pkt, "tapc2234cd0-55", pkt, "tap1589a2b3-22")

    # Inject the packet from hbf-r to vrouter
    # Encode the flow id in the src mac of the packet
    eth = Ether(dst='02:e7:03:ea:67:f1', src='ca:f1:00:00:d9:d4', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='icmp', src='1.0.0.3', dst='1.0.0.5')
    icmp = ICMP(type=8, code=0, id=4145)
    pkt = eth/ip/icmp
    pkt.show()

    # Send it to hbf-r
    vt.send_recv_pkt(pkt, "tap8b05a86b-36", pkt, "1")
