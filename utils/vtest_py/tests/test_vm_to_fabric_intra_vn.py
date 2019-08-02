#!/usr/bin/python

import os
import sys
import ipaddress
import socket
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib')
import vtconst
from vtest_lib import *

'''
vif --list
-----------
[root@10c591d9a769 vtest_py]# /root/contrail/build/debug/vrouter/utils/vif --sock-dir /root/contrail/build/debug/vrouter/utils/vtest_py_venv/sock_dir --list
Vrouter Interface Table

Flags: P=Policy, X=Cross Connect, S=Service Chain, Mr=Receive Mirror
       Mt=Transmit Mirror, Tc=Transmit Checksum Offload, L3=Layer 3, L2=Layer 2
       D=DHCP, Vp=Vhost Physical, Pr=Promiscuous, Vnt=Native Vlan Tagged
       Mnp=No MAC Proxy, Dpdk=DPDK PMD Interface, Rfl=Receive Filtering Offload, Mon=Interface is Monitored
       Uuf=Unknown Unicast Flood, Vof=VLAN insert/strip offload, Df=Drop New Flows, L=MAC Learning Enabled
       Proxy=MAC Requests Proxied Always, Er=Etree Root, Mn=Mirror without Vlan Tag, Ig=Igmp Trap Enabled

vif0/0      PCI: Mock
            Type:Physical HWaddr:00:1b:21:bb:f9:48 IPaddr:0.0.0.0
            Vrf:0 Mcast Vrf:65535 Flags:L3L2Vp QOS:0 Ref:6
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:1  bytes:0 errors:0
            Drops:0

vif0/1      PMD: vhost0 Mock
            Type:Host HWaddr:00:1b:21:bb:f9:48 IPaddr:8.0.0.2
            Vrf:0 Mcast Vrf:65535 Flags:L3D QOS:0 Ref:6
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

vif0/2      Socket: unix Mock
            Type:Agent HWaddr:00:00:5e:00:01:00 IPaddr:0.0.0.0
            Vrf:65535 Mcast Vrf:65535 Flags:L3 QOS:0 Ref:5
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

vif0/5      PMD: tapc2234cd0-55
            Type:Virtual HWaddr:00:00:5e:00:01:00 IPaddr:1.1.1.3
            Vrf:5 Mcast Vrf:5 Flags:PL3L2D QOS:0 Ref:6
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:1  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0


nh --list
---------
[root@10c591d9a769 vtest_py]# /root/contrail/build/debug/vrouter/utils/nh --sock-dir /root/contrail/build/debug/vrouter/utils/vtest_py_venv/sock_dir --list
Id:0          Type:Drop           Fmly: AF_INET  Rid:0  Ref_cnt:1          Vrf:0
              Flags:Valid,

Id:21         Type:Tunnel         Fmly: AF_INET  Rid:0  Ref_cnt:2          Vrf:0
              Flags:Valid, MPLSoUDP, Etree Root,
              Oif:1 Len:14 Data:00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00
              Sip:8.0.0.2 Dip:8.0.0.3

Id:38         Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:1          Vrf:5
              Flags:Valid, Policy,
              EncapFmly:0000 Oif:5 Len:14
              Encap Data: 02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00

flow -l
-------
[root@10c591d9a769 vtest_py]# /root/contrail/build/debug/vrouter/utils/flow --sock-dir /root/contrail/build/debug/vrouter/utils/vtest_py_venv/sock_dir -l
Flow table(size 80609280, entries 629760)

Entries: Created 0 Added 2 Deleted 0 Changed 1Processed 0 Used Overflow entries 0
(Created Flows/CPU: 0 0 0 0 0 0 0 0 0 0 0)(oflows 0)

Action:F=Forward, D=Drop N=NAT(S=SNAT, D=DNAT, Ps=SPAT, Pd=DPAT, L=Link Local Port)
 Other:K(nh)=Key_Nexthop, S(nh)=RPF_Nexthop
 Flags:E=Evicted, Ec=Evict Candidate, N=New Flow, M=Modified Dm=Delete Marked
TCP(r=reverse):S=SYN, F=FIN, R=RST, C=HalfClose, E=Established, D=Dead

    Index                Source:Port/Destination:Port                      Proto(V)
-----------------------------------------------------------------------------------
    55764<=>385300       1.1.1.3:4145                                        1 (5)
                         1.1.1.5:0
(Gen: 1, K(nh):38, Action:F, Flags:, QOS:-1, S(nh):38,  Stats:0/0,  SPort 52018,
 TTL 0, Sinfo 0.0.0.0)

   385300<=>55764        1.1.1.5:4145                                        1 (5)
                         1.1.1.3:0
(Gen: 1, K(nh):38, Action:F, Flags:, QOS:-1, S(nh):21,  Stats:0/0,  SPort 55597,
 TTL 0, Sinfo 0.0.0.0)

rt --dump 5
-----------
[root@10c591d9a769 vtest_py]# /root/contrail/build/debug/vrouter/utils/rt --sock-dir /root/contrail/build/debug/vrouter/utils/vtest_py_venv/sock_dir --dump 5 --family bridge
Flags: L=Label Valid, Df=DHCP flood, Mm=Mac Moved, L2c=L2 Evpn Control Word, N=New Entry, Ec=EvpnControlProcessing
vRouter bridge table 0/5
Index       DestMac                  Flags           Label/VNID      Nexthop           Stats
92304       2:e7:3:ea:67:f1            LDf                   27           21               1

'''
def test_vm_to_fabric_intra_vn(vrouter_test_fixture):

    vt = vtest("test_vm_to_fabric_intra_vn")

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
    nh.nhr_type = vtconst.NH_TYPE_ENCAP
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
    nh.nhr_type = vtconst.NH_TYPE_TUNNEL
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
    flow.fr_op = vtconst.FLOW_OPER_SET
    flow.fr_flow_sip_l = vt_ipv4("1.1.1.3")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("1.1.1.5")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = -1
    flow.fr_rindex = -1
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE
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
    flow.fr_op = vtconst.FLOW_OPER_SET
    flow.fr_flow_sip_l = vt_ipv4("1.1.1.5")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("1.1.1.3")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = -1
    flow.fr_rindex = int(fr_indx)
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE | vtconst.VR_RFLOW_VALID
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
    flow.fr_op = vtconst.FLOW_OPER_SET
    flow.fr_flow_sip_l = vt_ipv4("1.1.1.3")
    flow.fr_flow_sip_u = 0
    flow.fr_flow_dip_l = vt_ipv4("1.1.1.5")
    flow.fr_flow_dip_u = 0
    flow.fr_family = socket.AF_INET
    flow.fr_index = int(fr_indx)
    flow.fr_rindex = int(rfr_indx)
    flow.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE | vtconst.VR_RFLOW_VALID
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

    eth = Ether(dst='02:e7:03:ea:67:f1', src='02:c2:23:4c:d0:55', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='icmp', src='1.1.1.3', dst='1.1.1.5')
    icmp = ICMP(type=8, code=0, id=4145)
    pkt = eth/ip/icmp
    pkt.show()

    # send packet
    vt.send_pkt(pkt, "tapc2234cd0-55")

    # Check if the packet was sent to tenant vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_GET
    vif.vifr_idx = 0
    vif_resp_file = vt.send_sandesh_req(vif, vt.VT_RESPONSE_REQD)
    vif_opackets = vt.parse_xml_field(vif_resp_file, "vifr_opackets")
    assert (vif_opackets.find("1") != -1), "Failed to receive packet"
