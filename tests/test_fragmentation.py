#!/usr/bin/python

from topo_base.vm_to_fabric_intra_vn import VmToFabricIntraVn
import pytest
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


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
            Type:Virtual HWaddr:00:00:5e:00:01:00 IPaddr:1.0.0.3
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
55764<=>385300       1.0.0.3:4145                                   1 (5)
                     1.0.0.5:0
(Gen: 1, K(nh):38, Action:F, Flags:, QOS:-1, S(nh):38,  Stats:0/0,
SPort 52018, TTL 0, Sinfo 0.0.0.0)

385300<=>55764        1.0.0.5:4145                                  1 (5)
                      1.0.0.3:0
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


class TestFragmentation(VmToFabricIntraVn):

    def test_fragmentation_with_flow(self):

        # create ping request
        icmp = IcmpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            smac='02:c2:23:4c:d0:55',
            dmac='02:e7:03:ea:67:f1',
            id=4145,
            size=512)
        pkt = icmp.get_packet()
        pkt.show()
        frags = fragment(pkt, fragsize=128)

        # send fragments from tenant_vif
        rcv = self.tenant_vif.send_and_receive_packet(frags, self.fabric_vif)

        # Check if all the fragments are sent to tenant vif
        self.assertIsNotNone(rcv)
        self.assertEqual(len(frags), self.fabric_vif.get_vif_opackets())
        self.assertEqual(len(frags), len(rcv))

    def test_fragmentation_ooo_with_flow(self):

        # create ping request
        icmp = IcmpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            smac='02:c2:23:4c:d0:55',
            dmac='02:e7:03:ea:67:f1',
            id=4145,
            size=512)
        pkt = icmp.get_packet()
        pkt.show()
        frags = fragment(pkt, fragsize=128)

        # save the head fragment
        head_frag = frags.pop(0)

        drop_stats = DropStats()
        frag_errors_prev = drop_stats.get_vds_fragment_errors()

        # send all execpt head-fragment from tenant_vif
        rcv = self.tenant_vif.send_packet(frags)
        time.sleep(6)

        # Check if all packets are dropped as frag errors
        drop_stats.reload()
        frag_errors_new = drop_stats.get_vds_fragment_errors()
        self.assertEqual(len(frags), frag_errors_new - frag_errors_prev)

        # insert the head-fragment at the end
        frags.append(head_frag)

        # send the fragments
        rcv = self.tenant_vif.send_packet(frags)
        time.sleep(3)

        # Check if all the fragments are sent to tenant vif
        self.assertEqual(len(frags), self.fabric_vif.get_vif_opackets())

    def test_fragmentation_ecmp_with_flow(self):

        # Add another tunnel NH
        self.tunnel2_nh = TunnelNextHopV4(
            encap_oif_id=self.fabric_vif.idx(),
            encap="00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00",
            tun_sip="8.0.0.2",
            tun_dip="8.0.0.4",
            nh_idx=22,
            nh_flags=constants.NH_FLAG_TUNNEL_UDP_MPLS |
            constants.NH_FLAG_ETREE_ROOT)
        self.tunnel2_nh.sync()

        # Create and add composite NH for both tunnel NH's
        self.composite_nh = CompositeNextHop(
                nh_idx=23,
                nh_flags=constants.NH_FLAG_COMPOSITE_ECMP)
        self.composite_nh.add_nexthop(121, self.tunnel_nh.idx())
        self.composite_nh.add_nexthop(122, self.tunnel2_nh.idx())
        self.composite_nh.sync()

        # Update bridge route to point to composite NH
        self.bridge_route.rtr_nh_id = 23
        self.bridge_route.sync()

        # create ping request
        icmp = IcmpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            smac='02:c2:23:4c:d0:55',
            dmac='02:e7:03:ea:67:f1',
            id=4145,
            size=512)
        pkt = icmp.get_packet()
        pkt.show()
        frags = fragment(pkt, fragsize=128)

        # send fragments from tenant_vif
        rcv = self.tenant_vif.send_and_receive_packet(frags, self.fabric_vif)

        # Check if all the fragments are sent to tenant vif
        self.assertIsNotNone(rcv)
        self.assertEqual(len(frags), self.fabric_vif.get_vif_opackets())
        self.assertEqual(len(frags), len(rcv))

    def test_fragmentation_without_flow(self):

        # delete the flows
        self.f_flow.delete()
        self.r_flow.delete()

        # Remove policy flag from vif
        self.tenant_vif.vifr_flags &= ~constants.VIF_FLAG_POLICY_ENABLED
        self.tenant_vif.sync()

        # create ping request
        icmp = IcmpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            smac='02:c2:23:4c:d0:55',
            dmac='02:e7:03:ea:67:f1',
            id=4145,
            size=512)
        pkt = icmp.get_packet()
        pkt.show()
        frags = fragment(pkt, fragsize=128)

        # send fragments from tenant_vif
        rcv = self.tenant_vif.send_and_receive_packet(frags, self.fabric_vif)

        # Check if all the fragments are sent to tenant vif
        self.assertIsNotNone(rcv)
        self.assertEqual(len(frags), self.fabric_vif.get_vif_opackets())
        self.assertEqual(len(frags), len(rcv))

    def test_fragmentation_ooo_without_flow(self):

        # delete the flows
        self.f_flow.delete()
        self.r_flow.delete()

        # Remove policy flag from vif
        self.tenant_vif.vifr_flags &= ~constants.VIF_FLAG_POLICY_ENABLED
        self.tenant_vif.sync()

        # create ping request
        icmp = IcmpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            smac='02:c2:23:4c:d0:55',
            dmac='02:e7:03:ea:67:f1',
            id=4145,
            size=512)
        pkt = icmp.get_packet()
        pkt.show()
        frags = fragment(pkt, fragsize=128)

        # put head fragment at the end
        head_frag = frags.pop(0)
        frags.append(head_frag)

        # send all execpt head-fragment from tenant_vif
        rcv = self.tenant_vif.send_packet(frags)
        time.sleep(3)

        # Check if all the fragments are sent to tenant vif
        self.assertEqual(len(frags), self.fabric_vif.get_vif_opackets())

    def test_fragmentation_ecmp_without_flow(self):

        # delete the flows
        self.f_flow.delete()
        self.r_flow.delete()

        # Remove policy flag from vif
        self.tenant_vif.vifr_flags &= ~constants.VIF_FLAG_POLICY_ENABLED
        self.tenant_vif.sync()

        # Add another tunnel NH
        self.tunnel2_nh = TunnelNextHopV4(
            encap_oif_id=self.fabric_vif.idx(),
            encap="00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00",
            tun_sip="8.0.0.2",
            tun_dip="8.0.0.4",
            nh_idx=22,
            nh_flags=constants.NH_FLAG_TUNNEL_UDP_MPLS |
            constants.NH_FLAG_ETREE_ROOT)
        self.tunnel2_nh.sync()

        # Create and add composite NH for both tunnel NH's
        self.composite_nh = CompositeNextHop(
                nh_idx=23,
                nh_flags=constants.NH_FLAG_COMPOSITE_ECMP)
        self.composite_nh.add_nexthop(121, self.tunnel_nh.idx())
        self.composite_nh.add_nexthop(122, self.tunnel2_nh.idx())
        self.composite_nh.sync()

        # Update bridge route to point to composite NH
        self.bridge_route.rtr_nh_id = 23
        self.bridge_route.sync()

        # create ping request
        icmp = IcmpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            smac='02:c2:23:4c:d0:55',
            dmac='02:e7:03:ea:67:f1',
            id=4145,
            size=512)
        pkt = icmp.get_packet()
        pkt.show()
        frags = fragment(pkt, fragsize=128)

        # send fragments from tenant_vif
        rcv = self.tenant_vif.send_and_receive_packet(frags, self.fabric_vif)

        # Check if all the fragments are sent to tenant vif
        self.assertIsNotNone(rcv)
        self.assertEqual(len(frags), self.fabric_vif.get_vif_opackets())
        self.assertEqual(len(frags), len(rcv))

    def test_fragmentation_ecmp_ooo_without_flow(self):

        # delete the flows
        self.f_flow.delete()
        self.r_flow.delete()

        # Remove policy flag from vif
        self.tenant_vif.vifr_flags &= ~constants.VIF_FLAG_POLICY_ENABLED
        self.tenant_vif.sync()

        # Add another tunnel NH
        self.tunnel2_nh = TunnelNextHopV4(
            encap_oif_id=self.fabric_vif.idx(),
            encap="00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00",
            tun_sip="8.0.0.2",
            tun_dip="8.0.0.4",
            nh_idx=22,
            nh_flags=constants.NH_FLAG_TUNNEL_UDP_MPLS |
            constants.NH_FLAG_ETREE_ROOT)
        self.tunnel2_nh.sync()

        # Create and add composite NH for both tunnel NH's
        self.composite_nh = CompositeNextHop(
                nh_idx=23,
                nh_flags=constants.NH_FLAG_COMPOSITE_ECMP)
        self.composite_nh.add_nexthop(121, self.tunnel_nh.idx())
        self.composite_nh.add_nexthop(122, self.tunnel2_nh.idx())
        self.composite_nh.sync()

        # Update bridge route to point to composite NH
        self.bridge_route.rtr_nh_id = 23
        self.bridge_route.sync()

        # create ping request
        icmp = IcmpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            smac='02:c2:23:4c:d0:55',
            dmac='02:e7:03:ea:67:f1',
            id=4145,
            size=512)
        pkt = icmp.get_packet()
        pkt.show()
        frags = fragment(pkt, fragsize=128)

        # save the head fragment
        head_frag = frags.pop(0)

        # send all execpt head-fragment from tenant_vif
        rcv = self.tenant_vif.send_packet(frags)
        time.sleep(6)

        # Check if all packets are dropped as frag errors
        drop_stats = DropStats()
        self.assertEqual(len(frags), drop_stats.get_vds_fragment_errors())

        # insert the head-fragment at the end
        frags.append(head_frag)

        # send the fragments
        rcv = self.tenant_vif.send_packet(frags)
        time.sleep(3)

        # Check if all the fragments are sent to tenant vif
        self.assertEqual(len(frags), self.fabric_vif.get_vif_opackets())
