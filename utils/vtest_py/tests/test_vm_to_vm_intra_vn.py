#!/usr/bin/python

import os
import sys
import ipaddress
import socket
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
import vtconst
from vtest_lib import *

'''
vif --list
-----------

[root@090c8246aecd vtest_py]# $utils/vif --sock-dir $sock --list
Vrouter Interface Table

Flags: P=Policy, X=Cross Connect, S=Service Chain, Mr=Receive Mirror
       Mt=Transmit Mirror, Tc=Transmit Checksum Offload, L3=Layer 3, L2=Layer 2
       D=DHCP, Vp=Vhost Physical, Pr=Promiscuous, Vnt=Native Vlan Tagged
       Mnp=No MAC Proxy, Dpdk=DPDK PMD Interface, Rfl=Receive Filtering Offload, Mon=Interface is Monitored
       Uuf=Unknown Unicast Flood, Vof=VLAN insert/strip offload, Df=Drop New Flows, L=MAC Learning Enabled
       Proxy=MAC Requests Proxied Always, Er=Etree Root, Mn=Mirror without Vlan Tag, HbsL=HBS Left Intf
       HbsR=HBS Right Intf, Ig=Igmp Trap Enabled

vif0/3      PMD: tap88670c2e-11
            Type:Virtual HWaddr:00:00:5e:00:01:00 IPaddr:1.1.1.4
            Vrf:2 Mcast Vrf:2 Flags:PL3L2D QOS:0 Ref:7
            RX port   packets:1 errors:0 syscalls:1
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:1  bytes:42 errors:0
            TX packets:1  bytes:42 errors:0
            Drops:0
            TX port   packets:1 errors:0 syscalls:1

vif0/4      PMD: tape703ea67-f1
            Type:Virtual HWaddr:00:00:5e:00:01:00 IPaddr:1.1.1.5
            Vrf:2 Mcast Vrf:2 Flags:PL3L2D QOS:0 Ref:7
            RX port   packets:1 errors:0 syscalls:1
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:1  bytes:42 errors:0
            TX packets:1  bytes:42 errors:0
            Drops:0
            TX port   packets:1 errors:0 syscalls:1

rt --dump 2 --family bridge
----------------------------
[root@090c8246aecd vtest_py]# $utils/rt --sock-dir $sock --dump 2 --family bridge
Flags: L=Label Valid, Df=DHCP flood, Mm=Mac Moved, L2c=L2 Evpn Control Word, N=New Entry, Ec=EvpnControlProcessing
vRouter bridge table 0/2
Index       DestMac                  Flags           Label/VNID      Nexthop           Stats
1256        2:e7:3:ea:67:f1                                   -           32               1
7480        2:88:67:c:2e:11                                   -           27               1
[root@090c8246aecd vtest_py]#

flow -l
-------
[root@090c8246aecd vtest_py]# $utils/flow --sock-dir $sock -l
Flow table(size 161218560, entries 629760)

Entries: Created 0 Added 2 Deleted 0 Changed 1Processed 0 Used Overflow entries 0
(Created Flows/CPU: 0 0 0 0 0 0 0 0 0 0 0)(oflows 0)

Action:F=Forward, D=Drop N=NAT(S=SNAT, D=DNAT, Ps=SPAT, Pd=DPAT, L=Link Local Port)
 Other:K(nh)=Key_Nexthop, S(nh)=RPF_Nexthop
 Flags:E=Evicted, Ec=Evict Candidate, N=New Flow, M=Modified Dm=Delete Marked
TCP(r=reverse):S=SYN, F=FIN, R=RST, C=HalfClose, E=Established, D=Dead

    Index                Source:Port/Destination:Port                      Proto(V)
-----------------------------------------------------------------------------------
   147464<=>239712       1.1.1.4:1136                                        1 (2)
                         1.1.1.5:0
(Gen: 1, K(nh):23, Action:F, Flags:, QOS:-1, S(nh):23,  Stats:1/42,  SPort 59275,
 TTL 0, Sinfo 3.0.0.0)

   239712<=>147464       1.1.1.5:1136                                        1 (2)
                         1.1.1.4:0
(Gen: 1, K(nh):28, Action:F, Flags:, QOS:-1, S(nh):28,  Stats:1/42,  SPort 51988,
 TTL 0, Sinfo 4.0.0.0)

nh --list
---------
[root@090c8246aecd vtest_py]# $utils/nh --sock-dir $sock --list
Id:0          Type:Drop           Fmly: AF_INET  Rid:0  Ref_cnt:1          Vrf:0
              Flags:Valid,

Id:23         Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:1          Vrf:2
              Flags:Valid, Policy, Etree Root,
              EncapFmly:0000 Oif:3 Len:14
              Encap Data: 02 88 67 0c 2e 11 00 00 5e 00 01 00 08 00

Id:27         Type:Encap          Fmly:AF_BRIDGE  Rid:0  Ref_cnt:2          Vrf:2
              Flags:Valid, Policy, Etree Root,
              EncapFmly:0000 Oif:3 Len:14
              Encap Data: 02 88 67 0c 2e 11 00 00 5e 00 01 00 08 00

Id:28         Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:1          Vrf:2
              Flags:Valid, Policy, Etree Root,
              EncapFmly:0000 Oif:4 Len:14
              Encap Data: 02 e7 03 ea 67 f1 00 00 5e 00 01 00 08 00

Id:32         Type:Encap          Fmly:AF_BRIDGE  Rid:0  Ref_cnt:2          Vrf:2
              Flags:Valid, Policy, Etree Root,
              EncapFmly:0000 Oif:4 Len:14
              Encap Data: 02 e7 03 ea 67 f1 00 00 5e 00 01 00 08 00
'''
@pytest.mark.skip(reason="failing because of vr_uvh_cl_timer_setup() not setup")
def test_vm_to_vm_intra_vn(vrouter_test_fixture):

    vt = vtest("test_vm_to_vm_intra_vn")

    # Add tenant vif3
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 3
    vif.vifr_mcast_vrf = 2
    vif.vifr_name = "tap88670c2e-11"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 2
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
    vif.vifr_mcast_vrf = 2
    vif.vifr_name = "tape703ea67-f1"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 2
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("1.1.1.5")
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
    nh.nhr_vrf = 2
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
    nh.nhr_vrf = 2
    nh.nhr_flags = vtconst.NH_FLAG_VALID | \
                   vtconst.NH_FLAG_POLICY_ENABLED |\
                   vtconst.NH_FLAG_ETREE_ROOT
    nh.nhr_family = socket.AF_INET

    vt.send_sandesh_req(nh)

    # Add vif3 Nexthop (bridge)
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_TYPE_ENCAP
    nh.nhr_id = 27
    nh.nhr_encap_oif_id = 3
    nh.nhr_encap = vt_encap("02 88 67 0c 2e 11 00 00 5e 00 01 00 08 00")
    nh.nhr_vrf = 2
    nh.nhr_flags = vtconst.NH_FLAG_VALID | \
                   vtconst.NH_FLAG_POLICY_ENABLED |\
                   vtconst.NH_FLAG_ETREE_ROOT
    nh.nhr_family = vtconst.AF_BRIDGE

    vt.send_sandesh_req(nh)

    # Add vif4 Nexthop (bridge)
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_TYPE_ENCAP
    nh.nhr_id = 32
    nh.nhr_encap_oif_id = 4
    nh.nhr_encap = vt_encap("02 e7 03 ea 67 f1 00 00 5e 00 01 00 08 00")
    nh.nhr_vrf = 2
    nh.nhr_flags = vtconst.NH_FLAG_VALID | \
                   vtconst.NH_FLAG_POLICY_ENABLED |\
                   vtconst.NH_FLAG_ETREE_ROOT
    nh.nhr_family = vtconst.AF_BRIDGE

    vt.send_sandesh_req(nh)

    # Add bridge Route
    route = vr_route_req()
    route.h_op = vtconst.SANDESH_OPER_ADD
    route.rtr_family = vtconst.AF_BRIDGE
    route.rtr_nh_id = 32
    route.rtr_mac = vt_mac("02:e7:03:ea:67:f1")
    route.rtr_vrf_id = 2

    vt.send_sandesh_req(route)

    # Add bridge Route
    route = vr_route_req()
    route.h_op = vtconst.SANDESH_OPER_ADD
    route.rtr_family = vtconst.AF_BRIDGE
    route.rtr_nh_id = 27
    route.rtr_mac = vt_mac("02:88:67:0c:2e:11")
    route.rtr_vrf_id = 2

    vt.send_sandesh_req(route)

    #Add forward Flow
    flow = vr_flow_req()
    flow.fr_op = vtconst.FLOW_OPER_SET
    flow.fr_flow_sip_l = vt_ipv4("1.1.1.4")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("1.1.1.5")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = -1
    flow.fr_rindex = -1
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE
    flow.fr_flow_proto = vtconst.VR_IP_PROTO_ICMP
    flow.fr_flow_sport = socket.htons(1136)
    flow.fr_flow_nh_id = 23
    flow.fr_src_nh_index = 23
    flow.fr_qos_id = -1
    flow.fr_action = vtconst.VR_FLOW_ACTION_FORWARD
    flow.fr_flow_dport = 0
    flow.fr_ecmp_nh_index = -1
    flow.fr_flow_vrf = 2
    flow.rflow_sip_u = 0
    flow.rflow_sip_l = vt_ipv4("1.1.1.5")
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
    flow.fr_flow_sip_l = vt_ipv4("1.1.1.5")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("1.1.1.4")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = -1
    flow.fr_rindex = int(fr_indx)
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE | vtconst.VR_RFLOW_VALID
    flow.fr_flow_proto = vtconst.VR_IP_PROTO_ICMP
    flow.fr_flow_sport = socket.htons(1136)
    flow.fr_flow_nh_id = 28
    flow.fr_src_nh_index = 28
    flow.fr_qos_id = -1
    flow.fr_action = vtconst.VR_FLOW_ACTION_FORWARD
    flow.fr_flow_dport = 0
    flow.fr_ecmp_nh_index = -1
    flow.fr_flow_vrf = 2
    flow.rflow_sip_u = 0
    flow.rflow_sip_l = vt_ipv4("1.1.1.4")
    flow.rflow_dip_u = 0
    flow.rflow_dip_l = vt_ipv4("1.1.1.5")
    flow.rflow_nh_id = 23
    flow.rflow_sport = socket.htons(1136)

    resp_file = vt.send_sandesh_req(flow, vt.VT_RESPONSE_REQD)

    rfr_indx = vt.parse_xml_field(resp_file, "fresp_index")

    # Update forward flow
    flow = vr_flow_req()
    flow.fr_op = vtconst.FLOW_OPER_SET
    flow.fr_flow_sip_l = vt_ipv4("1.1.1.4")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("1.1.1.5")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = int(fr_indx)
    flow.fr_rindex = int(rfr_indx)
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE | vtconst.VR_RFLOW_VALID
    flow.fr_flow_proto = vtconst.VR_IP_PROTO_ICMP
    flow.fr_flow_sport = socket.htons(1136)
    flow.fr_flow_nh_id = 23
    flow.fr_src_nh_index = 23
    flow.fr_gen_id = int(fr_genid)
    flow.fr_qos_id = -1
    flow.fr_action = vtconst.VR_FLOW_ACTION_FORWARD
    flow.fr_flow_dport = 0
    flow.fr_ecmp_nh_index = -1
    flow.fr_flow_vrf = 2
    flow.rflow_sip_u = 0
    flow.rflow_sip_l = vt_ipv4("1.1.1.5")
    flow.rflow_dip_u = 0
    flow.rflow_dip_l = vt_ipv4("1.1.1.4")
    flow.rflow_nh_id = 28
    flow.rflow_sport = socket.htons(1136)

    resp_file = vt.send_sandesh_req(flow, vt.VT_RESPONSE_REQD)

    fr_indx = vt.parse_xml_field(resp_file, "fresp_index")

    # send ping request from vif3
    eth = Ether(src='02:88:67:0c:2e:11', dst='02:e7:03:ea:67:f1', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='icmp', dst='1.1.1.5', src='1.1.1.4')
    icmp = ICMP(type=8, code=0, id=1136)
    pkt = eth/ip/icmp
    pkt.show()

    # send packet
    vt.send_recv_pkt(pkt, "tap88670c2e-11", pkt, "tape703ea67-f1")

    # send ping response from vif4
    eth = Ether(dst='02:88:67:0c:2e:11', src='02:e7:03:ea:67:f1', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='icmp', src='1.1.1.5', dst='1.1.1.4')
    icmp = ICMP(type=0, code=0, id=1136)
    pkt = eth/ip/icmp
    pkt.show()

    # send packet
    vt.send_recv_pkt(pkt, "tape703ea67-f1", pkt, "tap88670c2e-11")

    # Check if the packet was received at vif3 and vif4
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
