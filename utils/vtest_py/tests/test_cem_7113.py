#!/usr/bin/python

import os
import sys
import ipaddress
import socket
sys.path.append(os.getcwd())
import vtconst
from vtest_lib import *

def test_cem_7713(vrouter_test_fixture):

    vt = vtest("test_cem_7713")

    # Add fabric interface
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_PHYSICAL
    vif.vifr_idx = 0
    vif.vifr_name = "eth1"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 0
    vif.vifr_mcast_vrf = 65535
    vif.vifr_mac = vt_mac("00:1b:21:bb:f9:46")
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
    vif.vifr_mac = vt_mac("00:1b:21:bb:f9:46")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("8.0.0.3")
    vif.vifr_nh_id = 5
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

    # Add tenant vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 3
    vif.vifr_mcast_vrf = 2
    vif.vifr_name = "tape703ea67-f1"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 2
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("1.1.1.5")
    vif.vifr_nh_id = 21
    vif.vifr_flags = vtconst.VIF_FLAG_POLICY_ENABLED | vtconst.VIF_FLAG_DHCP_ENABLED

    vt.send_sandesh_req(vif)

    # Add tenant vif Nexthop
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_ENCAP
    nh.nhr_id = 21
    nh.nhr_encap_oif_id = 3
    nh.nhr_encap = vt_encap("02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00")
    nh.nhr_encap_family = vtconst.VR_ETH_PROTO_ARP
    nh.nhr_vrf = 2
    nh.nhr_flags = vtconst.NH_FLAG_VALID | vtconst.NH_FLAG_POLICY_ENABLED
    nh.nhr_family = socket.AF_INET

    vt.send_sandesh_req(nh)

    # Add vhost0 vif Nexthop
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_ENCAP
    nh.nhr_id = 5
    nh.nhr_encap_oif_id = 1
    nh.nhr_encap = vt_encap("00 1b 21 bb f9 46 00 1b 21 bb f9 46 08 00")
    nh.nhr_encap_family = vtconst.VR_ETH_PROTO_ARP
    nh.nhr_vrf = 0
    nh.nhr_flags = vtconst.NH_FLAG_VALID | vtconst.NH_FLAG_POLICY_ENABLED
    nh.nhr_family = socket.AF_INET

    vt.send_sandesh_req(nh)

    # Add fabric vif Nexthop
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_ENCAP
    nh.nhr_id = 16 
    nh.nhr_encap_oif_id = 0
    nh.nhr_encap = vt_encap("90 e2 ba 84 48 88 00 1b 21 bb f9 46 08 00")
    nh.nhr_encap_family = vtconst.VR_ETH_PROTO_ARP
    nh.nhr_vrf = 0
    nh.nhr_flags = vtconst.NH_FLAG_VALID
    nh.nhr_family = socket.AF_INET

    vt.send_sandesh_req(nh)

    # Add receive Nexthop
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_RCV
    nh.nhr_id = 10 
    nh.nhr_encap_oif_id = 1
    nh.nhr_vrf = 1
    nh.nhr_flags = vtconst.NH_FLAG_VALID | vtconst.NH_FLAG_RELAXED_POLICY
    nh.nhr_family = socket.AF_INET

    vt.send_sandesh_req(nh)

    # Add fabric Route
    route = vr_route_req()
    route.h_op = vtconst.SANDESH_OPER_ADD
    route.rtr_family = socket.AF_INET
    route.rtr_nh_id = 10
    route.rtr_prefix = vt_encap("08 00 00 03")
    route.rtr_prefix_len = 32
    route.rtr_vrf_id = 0
    route.rtr_label_flags = vtconst.VR_RT_ARP_TRAP_FLAG

    vt.send_sandesh_req(route)

    # Add tenant Route
    route = vr_route_req()
    route.h_op = vtconst.SANDESH_OPER_ADD
    route.rtr_family = socket.AF_INET
    route.rtr_nh_id = 21
    route.rtr_prefix = vt_encap("01 01 01 05")
    route.rtr_prefix_len = 32
    route.rtr_vrf_id = 2
    route.rtr_label_flags = vtconst.VR_RT_ARP_PROXY_FLAG

    vt.send_sandesh_req(route)

    #Add forward Flow
    flow = vr_flow_req()
    flow.fr_op = vtconst.FLOW_SET
    flow.fr_flow_sip_l = vt_ipv4("8.0.0.1")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("8.0.0.3")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = -1
    flow.fr_rindex = -1
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE |\
                    vtconst.VR_FLOW_FLAG_VRFT |\
                    vtconst.VR_FLOW_FLAG_SNAT |\
                    vtconst.VR_FLOW_FLAG_DNAT |\
                    vtconst.VR_FLOW_FLAG_DPAT |\
                    vtconst.VR_FLOW_FLAG_LINK_LOCAL
    flow.fr_flow_proto = vtconst.VR_IP_PROTO_UDP
    flow.fr_flow_sport = socket.htons(53)
    flow.fr_flow_nh_id = 5
    flow.fr_src_nh_index = 16
    flow.fr_qos_id = -1
    flow.fr_action = vtconst.VR_FLOW_ACTION_NAT
    flow.fr_flow_dport = socket.htons(60185) 
    flow.fr_ecmp_nh_index = -1
    flow.fr_flow_vrf = 0
    flow.fr_flow_dvrf = 2
    flow.rflow_sip_u = 0
    flow.rflow_sip_l = vt_ipv4("1.1.1.5")
    flow.rflow_dip_u = 0
    flow.rflow_dip_l = vt_ipv4("169.254.169.7")
    flow.rflow_nh_id = 21
    flow.rflow_sport = socket.htons(33596)

    resp_file = vt.send_sandesh_req(flow, vt.VT_RESPONSE_REQD)

    fr_indx = vt.parse_xml_field(resp_file, "fresp_index")
    fr_genid = vt.parse_xml_field(resp_file, "fresp_gen_id")

    #Add reverse Flow
    flow = vr_flow_req()
    flow.fr_op = vtconst.FLOW_SET
    flow.fr_flow_sip_l = vt_ipv4("1.1.1.5")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("169.254.169.7")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = -1
    flow.fr_rindex = int(fr_indx)
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE |\
                    vtconst.VR_RFLOW_VALID |\
                    vtconst.VR_FLOW_FLAG_VRFT |\
                    vtconst.VR_FLOW_FLAG_SNAT |\
                    vtconst.VR_FLOW_FLAG_DNAT |\
                    vtconst.VR_FLOW_FLAG_SPAT
    flow.fr_flow_proto = vtconst.VR_IP_PROTO_UDP
    flow.fr_flow_sport = socket.htons(33596)
    flow.fr_flow_nh_id = 21
    flow.fr_src_nh_index = 21
    flow.fr_qos_id = -1
    flow.fr_action = vtconst.VR_FLOW_ACTION_NAT
    flow.fr_flow_dport = socket.htons(53)
    flow.fr_ecmp_nh_index = -1
    flow.fr_flow_vrf = 2
    flow.fr_flow_dvrf = 0
    flow.rflow_sip_u = 0
    flow.rflow_sip_l = vt_ipv4("8.0.0.1")
    flow.rflow_dip_u = 0
    flow.rflow_dip_l = vt_ipv4("8.0.0.3")
    flow.rflow_nh_id = 5
    flow.rflow_sport = socket.htons(53)

    resp_file = vt.send_sandesh_req(flow, vt.VT_RESPONSE_REQD)

    rfr_indx = vt.parse_xml_field(resp_file, "fresp_index")

    # Update forward flow
    flow = vr_flow_req()
    flow.fr_op = vtconst.FLOW_SET
    flow.fr_flow_sip_l = vt_ipv4("8.0.0.1")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("8.0.0.3")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = int(fr_indx)
    flow.fr_rindex = int(rfr_indx)
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE |\
                    vtconst.VR_RFLOW_VALID |\
                    vtconst.VR_FLOW_FLAG_VRFT |\
                    vtconst.VR_FLOW_FLAG_SNAT |\
                    vtconst.VR_FLOW_FLAG_DNAT |\
                    vtconst.VR_FLOW_FLAG_DPAT |\
                    vtconst.VR_FLOW_FLAG_LINK_LOCAL
    flow.fr_flow_proto = vtconst.VR_IP_PROTO_UDP
    flow.fr_flow_sport = socket.htons(53)
    flow.fr_flow_nh_id = 5
    flow.fr_src_nh_index = 16
    flow.fr_gen_id = int(fr_genid)
    flow.fr_qos_id = -1
    flow.fr_action = vtconst.VR_FLOW_ACTION_NAT
    flow.fr_flow_dport = socket.htons(60185)
    flow.fr_ecmp_nh_index = -1
    flow.fr_flow_vrf = 0
    flow.fr_flow_dvrf = 2
    flow.rflow_sip_u = 0
    flow.rflow_sip_l = vt_ipv4("1.1.1.5")
    flow.rflow_dip_u = 0
    flow.rflow_dip_l = vt_ipv4("169.254.169.7")
    flow.rflow_nh_id = 21
    flow.rflow_sport = socket.htons(33596)

    resp_file = vt.send_sandesh_req(flow, vt.VT_RESPONSE_REQD)

    fr_indx = vt.parse_xml_field(resp_file, "fresp_index")

    eth = Ether(dst='00:1b:21:bb:f9:46', src='90:e2:ba:84:48:88', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='udp', src='8.0.0.1', dst='8.0.0.3')
    udp = UDP(sport=53, dport=60185)
    dns = DNS()
    pkt = eth/ip/udp/dns
    pkt.show()

    # send packet
    vt.send_pkt(pkt, "eth1")

    # Check if the packet was sent to tenant vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_GET
    vif.vifr_idx = 3

    vif_resp_file = vt.send_sandesh_req(vif, vt.VT_RESPONSE_REQD)
    vif_opackets = vt.parse_xml_field(vif_resp_file, "vifr_opackets")
    assert (vif_opackets.find("1") != -1), "Failed to receive NATed packet"
