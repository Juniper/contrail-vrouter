#!/usr/bin/python

import os
import sys
import ipaddress
import socket
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
import vtconst
from vtest_lib import *

def test_hbf_fabric_to_vmi(vrouter_test_fixture):

    vt = vtest("test_hbf_fabric_to_vmi")

    # Add fabric interface
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_PHYSICAL
    vif.vifr_idx = 0
    vif.vifr_name = "eth1"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 0
    vif.vifr_mcast_vrf = 65535
    vif.vifr_mac = vt_mac("00:1b:21:bb:f9:48")
    vif.vifr_mtu = 1514
    vif.vifr_flags = vtconst.VIF_FLAG_VHOST_PHYS

    vt.send_sandesh_req(vif)

    # Add vhost0 vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_HOST
    vif.vifr_idx = 1
    vif.vifr_name = "vhost0"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 0
    vif.vifr_mcast_vrf = 65535
    vif.vifr_mac = vt_mac("00:1b:21:bb:f9:48")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("8.0.0.2")
    vif.vifr_flags = vtconst.VIF_FLAG_L3_ENABLED | vtconst.VIF_FLAG_DHCP_ENABLED

    vt.send_sandesh_req(vif)

    # Add agent vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_AGENT
    vif.vifr_idx = 2
    vif.vifr_name = "unix"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_SOCKET
    vif.vifr_vrf = 65535
    vif.vifr_mcast_vrf = 65535
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_flags = vtconst.VIF_FLAG_L3_ENABLED

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
    vif.vifr_mcast_vrf = 5
    vif.vifr_name = "tapc2234cd0-55"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 5
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("1.1.1.3")
    vif.vifr_nh_id = 38
    vif.vifr_flags = vtconst.VIF_FLAG_POLICY_ENABLED | vtconst.VIF_FLAG_DHCP_ENABLED

    vt.send_sandesh_req(vif)

    # Add vif Nexthop
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_ENCAP
    nh.nhr_id = 38
    nh.nhr_encap_oif_id = 5
    nh.nhr_encap = vt_encap("02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00")
    nh.nhr_vrf = 5
    nh.nhr_flags = vtconst.NH_FLAG_VALID | \
                   vtconst.NH_FLAG_POLICY_ENABLED |\
                   vtconst.NH_FLAG_ETREE_ROOT
    nh.nhr_family = socket.AF_INET

    vt.send_sandesh_req(nh)

    # Add underlay Receive NH
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_RCV
    nh.nhr_id = 10
    nh.nhr_encap_oif_id = 1
    nh.nhr_vrf = 1
    nh.nhr_family = socket.AF_INET
    nh.nhr_flags = vtconst.NH_FLAG_VALID |\
                   vtconst.NH_FLAG_RELAXED_POLICY|\
                   vtconst.NH_FLAG_ETREE_ROOT
    vt.send_sandesh_req(nh)

    # Add underlay Route
    route = vr_route_req()
    route.h_op = vtconst.SANDESH_OPER_ADD
    route.rtr_family = socket.AF_INET
    route.rtr_nh_id = 10
    route.rtr_prefix = vt_encap("08 00 00 02")
    route.rtr_prefix_len = 32
    route.rtr_vrf_id = 0
    route.rtr_label_flags = vtconst.VR_RT_ARP_TRAP_FLAG

    vt.send_sandesh_req(route)

    # Add Encap L2 Nexthop for overlay
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_ENCAP
    nh.nhr_id = 44
    nh.nhr_encap_oif_id = 5
    nh.nhr_encap = vt_encap("02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00")
    nh.nhr_vrf = 5
    nh.nhr_family = vtconst.AF_BRIDGE
    nh.nhr_flags = vtconst.NH_FLAG_VALID |\
                   vtconst.NH_FLAG_POLICY_ENABLED|\
                   vtconst.NH_FLAG_ETREE_ROOT

    vt.send_sandesh_req(nh)

    # Add bridge Route
    route = vr_route_req()
    route.h_op = vtconst.SANDESH_OPER_ADD
    route.rtr_family = vtconst.AF_BRIDGE
    route.rtr_nh_id = 44
    route.rtr_mac = vt_mac("02:c2:23:4c:d0:55")
    route.rtr_vrf_id = 5

    vt.send_sandesh_req(route)

    # Add MPLS entry for overlay
    mpls = vr_mpls_req()
    mpls.h_op = vtconst.SANDESH_OPER_ADD
    mpls.mr_label = 42
    mpls.mr_rid = 0
    mpls.mr_nhid = 44
    vt.send_sandesh_req(mpls)

    # Add tunnel NH (for src validation)
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_TUNNEL
    nh.nhr_id = 21
    nh.nhr_encap_oif_id = 0
    nh.nhr_encap = vt_encap("00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00")
    nh.nhr_tun_sip = vt_ipv4("8.0.0.2")
    nh.nhr_tun_dip = vt_ipv4("8.0.0.3")
    nh.nhr_vrf = 0
    nh.nhr_family = socket.AF_INET
    nh.nhr_flags = vtconst.NH_FLAG_VALID |\
                   vtconst.NH_FLAG_TUNNEL_UDP_MPLS |\
                   vtconst.NH_FLAG_ETREE_ROOT
    vt.send_sandesh_req(nh)

    #Add forward Flow
    flow = vr_flow_req()
    flow.fr_op = vtconst.FLOW_SET
    flow.fr_flow_sip_l = vt_ipv4("1.1.1.3")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("1.1.1.5")
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
    flow.rflow_sip_l = vt_ipv4("1.1.1.5")
    flow.rflow_dip_u = 0
    flow.rflow_dip_l = vt_ipv4("1.1.1.3")
    flow.rflow_nh_id = 21
    flow.rflow_sport = socket.htons(4145)

    resp_file = vt.send_sandesh_req(flow, vt.VT_RESPONSE_REQD)

    fr_indx = vt.parse_xml_field(resp_file, "fresp_index")
    fr_genid = vt.parse_xml_field(resp_file, "fresp_gen_id")

    #Add reverse Flow
    flow = vr_flow_req()
    flow.fr_op = vtconst.FLOW_SET
    flow.fr_flow_sip_l = vt_ipv4("1.1.1.5")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("1.1.1.3")
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
    flow.rflow_sip_l = vt_ipv4("1.1.1.3")
    flow.rflow_dip_u = 0
    flow.rflow_dip_l = vt_ipv4("1.1.1.5")
    flow.rflow_nh_id = 21
    flow.rflow_sport = socket.htons(4145)

    resp_file = vt.send_sandesh_req(flow, vt.VT_RESPONSE_REQD)

    rfr_indx = vt.parse_xml_field(resp_file, "fresp_index")

    # Update forward flow
    flow = vr_flow_req()
    flow.fr_op = vtconst.FLOW_SET
    flow.fr_flow_sip_l = vt_ipv4("1.1.1.3")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("1.1.1.5")
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
    flow.rflow_sip_l = vt_ipv4("1.1.1.5")
    flow.rflow_dip_u = 0
    flow.rflow_dip_l = vt_ipv4("1.1.1.3")
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

    # send mplsoudp packet from fabric
    load_contrib("mpls")
    eth_outer = Ether(dst='00:1b:21:bb:f9:48', src='00:1b:21:bb:f9:46', type=0x800)
    ip_outer = IP(version=4, ihl=5, id=10, ttl=64, proto='udp', src='8.0.0.3', dst='8.0.0.2')
    udp_outer = UDP(sport=53363, dport=6635)
    mpls = MPLS(label=42, ttl=64)
    eth_inner = Ether(src='02:e7:03:ea:67:f1', dst='02:c2:23:4c:d0:55', type=0x800)
    ip_inner = IP(version=4, ihl=5, id=1, ttl=64, proto='icmp', src='1.1.1.5', dst='1.1.1.3')
    icmp = ICMP(type=0, code=0, id=4145)
    pkt = eth_outer/ip_outer/udp_outer/mpls/eth_inner/ip_inner/icmp
    pkt.show()

    # Make sure the packet comes goes to hbf-r (tap8b05a86b-36)
    vt.send_recv_pkt(pkt, "eth1", pkt, "tap8b05a86b-36")

    # Inject the packet from hbf-l to vrouter
    # Encode the flow id in the dst mac of the packet
    eth = Ether(dst='c0:d2:00:06:44:7c', src='02:e7:03:ea:67:f1', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='icmp', src='1.0.0.5', dst='1.0.0.3')
    icmp = ICMP(type=0, code=0, id=4145)
    pkt = eth/ip/icmp
    pkt.show()

    # Send it to hbf-l
    vt.send_recv_pkt(pkt, "tap1589a2b3-22", pkt, "tapc2234cd0-55")

    # Check if the packet was sent to vrouter (by vtest) on fabric 
    # and received at vif5 (by vtest)
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_GET
    vif.vifr_idx = 0
    vif_resp_file = vt.send_sandesh_req(vif, vt.VT_RESPONSE_REQD)
    vif_ipackets = vt.parse_xml_field(vif_resp_file, "vifr_ipackets")
    assert (vif_ipackets.find("1") != -1), "Failed to receive packet"

    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_GET
    vif.vifr_idx = 5
    vif_resp_file = vt.send_sandesh_req(vif, vt.VT_RESPONSE_REQD)
    vif_opackets = vt.parse_xml_field(vif_resp_file, "vifr_opackets")
    assert (vif_opackets.find("1") != -1), "Failed to send packet"

    # Check if the packet was sent to hbs-r (by vrouter) 
    # and received at hbs-l (by vtest)
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_GET
    vif.vifr_idx = 4
    vif_resp_file = vt.send_sandesh_req(vif, vt.VT_RESPONSE_REQD)
    vif_opackets = vt.parse_xml_field(vif_resp_file, "vifr_opackets")
    assert (vif_opackets.find("1") != -1), "Failed to send packet"

    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_GET
    vif.vifr_idx = 3
    vif_resp_file = vt.send_sandesh_req(vif, vt.VT_RESPONSE_REQD)
    vif_ipackets = vt.parse_xml_field(vif_resp_file, "vifr_ipackets")
    assert (vif_opackets.find("1") != -1), "Failed to receive packet"
