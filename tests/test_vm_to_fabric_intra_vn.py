#!/usr/bin/python

from imports import *
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')

# anything with *test* will be assumed by pytest as a test
'''
vif --list
-----------
[root@10c591d9a769 vtest_py]# /root/contrail/build/debug/vrouter/utils/vif \
--sock-dir /root/contrail/build/debug/vrouter/utils/vtest_py_venv/sock_dir \
--list
Vrouter Interface Table

Flags: P=Policy, X=Cross Connect, S=Service Chain, Mr=Receive Mirror
       Mt=Transmit Mirror, Tc=Transmit Checksum Offload, L3=Layer 3,
       L2=Layer 2, D=DHCP, Vp=Vhost Physical, Pr=Promiscuous,
       Vnt=Native Vlan Tagged,Mnp=No MAC Proxy, Dpdk=DPDK PMD Interface,
       Rfl=Receive Filtering Offload,Mon=Interface is Monitored,
       Uuf=Unknown Unicast Flood, Vof=VLAN insert/strip offload,
       Df=Drop New Flows, L=MAC Learning Enabled,
       Proxy=MAC Requests Proxied Always, Er=Etree Root,
       Mn=Mirror without Vlan Tag, Ig=Igmp Trap Enabled

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
[root@10c591d9a769 vtest_py]# /root/contrail/build/debug/vrouter/utils/nh \
--sock-dir /root/contrail/build/debug/vrouter/utils/vtest_py_venv/sock_dir \
 --list
Id:0          Type:Drop           Fmly: AF_INET  Rid:0  Ref_cnt:1      Vrf:0
              Flags:Valid,

Id:21         Type:Tunnel         Fmly: AF_INET  Rid:0  Ref_cnt:2      Vrf:0
              Flags:Valid, MPLSoUDP, Etree Root,
              Oif:1 Len:14 Data:00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00
              Sip:8.0.0.2 Dip:8.0.0.3

Id:38         Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:1      Vrf:5
              Flags:Valid, Policy,
              EncapFmly:0000 Oif:5 Len:14
              Encap Data: 02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00

flow -l
-------
[root@10c591d9a769 vtest_py]# /root/contrail/build/debug/vrouter/utils/flow \
--sock-dir /root/contrail/build/debug/vrouter/utils/vtest_py_venv/sock_dir -l
Flow table(size 80609280, entries 629760)

Entries: Created 0 Added 2 Deleted 0 Changed 1Processed 0
Used Overflow entries 0
(Created Flows/CPU: 0 0 0 0 0 0 0 0 0 0 0)(oflows 0)

Action:F=Forward, D=Drop \
N=NAT(S=SNAT, D=DNAT, Ps=SPAT, Pd=DPAT, L=Link Local Port)
Other:K(nh)=Key_Nexthop, S(nh)=RPF_Nexthop
Flags:E=Evicted, Ec=Evict Candidate, N=New Flow, M=Modified Dm=Delete Marked
TCP(r=reverse):S=SYN, F=FIN, R=RST, C=HalfClose, E=Established, D=Dead

Index                Source:Port/Destination:Port                  Proto(V)
---------------------------------------------------------------------------
55764<=>385300       1.1.1.3:4145                                   1 (5)
                     1.1.1.5:0
(Gen: 1, K(nh):38, Action:F, Flags:, QOS:-1, S(nh):38,  Stats:0/0,
SPort 52018, TTL 0, Sinfo 0.0.0.0)

385300<=>55764        1.1.1.5:4145                                  1 (5)
                      1.1.1.3:0
(Gen: 1, K(nh):38, Action:F, Flags:, QOS:-1, S(nh):21,  Stats:0/0,
SPort 55597, TTL 0, Sinfo 0.0.0.0)

rt --dump 5
-----------
[root@10c591d9a769 vtest_py]# /root/contrail/build/debug/vrouter/utils/rt \
--sock-dir /root/contrail/build/debug/vrouter/utils/vtest_py_venv/sock_dir \
--dump 5 --family bridge
Flags: L=Label Valid, Df=DHCP flood, Mm=Mac Moved, L2c=L2 Evpn Control Word,
       N=New Entry, Ec=EvpnControlProcessing
vRouter bridge table 0/5
Index    DestMac              Flags       Label/VNID      Nexthop      Stats
92304    2:e7:3:ea:67:f1      LDf             27           21            1

'''


class TestFabricToVmInterVn(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()
        ObjectBase.set_auto_features(cleanup=True)

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def test_fabric_to_vm_inter_vn(self):

        # Add fabric interface
        fabric_interface = FabricVif(
            name="eth1",
            mac_str="00:1b:21:bb:f9:48")
        fabric_interface.sync()

        # Add vhost0 vif
        vhost0_vif = VhostVif(
            ipv4_str="8.0.0.2",
            mac_str="00:1b:21:bb:f9:48",
            idx=1,
            flags=constants.VIF_FLAG_L3_ENABLED)
        vhost0_vif.sync()

        # Add agent vif
        agent_vif = AgentVif(
            idx=2,
            flags=constants.VIF_FLAG_L3_ENABLED)
        agent_vif.sync()

        # Add tenant vif
        tenant_vif = VirtualVif(
            name="tapc2234cd0-55",
            ipv4_str="1.1.1.3",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=5,
            mcast_vrf=5,
            nh_idx=38)
        tenant_vif.sync()

        # Add vif Nexthop
        vif_nh = EncapNextHop(
            encap_oif_id=5,
            encap="02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00",
            nh_idx=38,
            nh_vrf=5,
            nh_flags=constants.NH_FLAG_POLICY_ENABLED)
        vif_nh.sync()

        # Add tunnel NH
        tunnel_nh = TunnelNextHopV4(
            encap_oif_id=0,
            encap="00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00",
            tun_sip="8.0.0.2",
            tun_dip="8.0.0.3",
            nh_idx=21,
            nh_flags=constants.NH_FLAG_TUNNEL_UDP_MPLS |
            constants.NH_FLAG_ETREE_ROOT)
        tunnel_nh.sync()

        # Add bridge Route
        bridge_route = BridgeRoute(
            vrf=5,
            mac_str="02:e7:03:ea:67:f1",
            nh_idx=21,
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG |
            constants.VR_RT_ARP_PROXY_FLAG |
            constants.VR_BE_FLOOD_DHCP_FLAG)
        bridge_route.sync()

        # Add forward and reverse flow and link them
        f_flow = InetFlow(
            sip='1.1.1.3',
            dip='1.1.1.5',
            sport=4145,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flow_nh_idx=38,
            ecmp_nh_index=-1,
            qos_id=-1,
            src_nh_idx=38,
            flow_vrf=5,
            ridx=-1,
            rflow_nh_idx=21)
        # Add hbs-l and hbs-r in the vrf table
        r_flow = InetFlow(
            sip='1.1.1.5',
            dip='1.1.1.3',
            sport=4145,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flow_nh_idx=38,
            flags=constants.VR_RFLOW_VALID,
            ecmp_nh_index=-1,
            qos_id=-1,
            src_nh_idx=21,
            flow_vrf=5,
            rflow_nh_idx=21)
        f_flow.sync_and_link_flow(r_flow)
        self.assertGreater(f_flow.get_fr_index(), 0)

        # send ping request from vif3
        icmp = IcmpPacket(
            sip='1.1.1.3',
            dip='1.1.1.5',
            smac='02:c2:23:4c:d0:55',
            dmac='02:e7:03:ea:67:f1',
            id=4145)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet
        tenant_vif.send_packet(pkt)

        # Check if the packet was sent to tenant vif
        self.assertEqual(1, fabric_interface.get_vif_opackets())
