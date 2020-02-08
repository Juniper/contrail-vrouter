#!/usr/bin/python

from imports import *
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')

# anything with *test* will be assumed by pytest as a test


class TestMirrorV6SandeshConf(unittest.TestCase):

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

    def test_mirror_v6_sandesh_conf(self):

        # Add the vif
        fabric_interface1 = FabricVif(
            name="eth0",
            mac_str="de:ad:be:ef:00:02",
            idx=1,
            mtu=2514,
            flags=0,
            mcast_vrf=None)

        # Add the vif
        fabric_interface2 = FabricVif(
            name="eth1",
            mac_str="de:ad:be:ef:00:01",
            idx=2,
            mtu=2514,
            flags=1,
            mcast_vrf=None)

        # Add the vif
        vif = VirtualVif(
            name="tap_1",
            ipv4_str=None,
            mac_str="de:ad:be:ef:00:01",
            idx=3,
            nh_idx=21,
            vrf=2,
            mtu=2514,
            flags=1)

        # Add Nexthop
        encap_nh = EncapNextHop(
            encap_oif_id=3,
            encap="de ad be ef 00 02 de ad be ef 00 01 08 00",
            nh_idx=21,
            nh_family=2,
            nh_vrf=2,
            nh_flags=3)

        # Add Nexthop
        tunnel_nh = TunnelNextHopV4(
            encap_oif_id=2,
            encap="de ad be ef 00 02 de ad be ef 00 01 08 00",
            tun_sip="2.2.1.1",
            tun_dip="1.1.2.2",
            nh_idx=14,
            nh_flags=129,
            nh_family=None)

        # Add Mirror
        mirr = Mirror(
            idx=1,
            nh_idx=14,
            flags=0,
            vni=50)

        # Add MPLS label
        mpls = Mpls(
            mr_label=48,
            mr_nhid=21)

        # Add Nexthop
        nhr = ReceiveNextHop(
            encap_oif_id=1,
            nh_idx=15,
            nh_family=2,
            nh_flags=257)

        # Add Route
        inet_route = InetRoute(
            vrf=0,
            prefix="2.2.1.1",
            nh_idx=15)
        ObjectBase.sync_all()

        # Add Flow
        inet6flow = Inet6Flow(
            sip6_str="00DE:00AD:00BE:00EF:0000:0000:0000:0001",
            dip6_str="00DE:00AD:00BE:00EF:0000:0000:0000:0002",
            sport=27648,
            dport=256,
            proto=17,
            flags=8193,
            flow_nh_idx=21,
            action=2,
            mirr_idx=1,
            extflags=2)
        inet6flow.sync(resp_required=True)

        udpv6_inner1 = Udpv6Packet(
            sport=27648,
            dport=256,
            sipv6='de:ad:be:ef::1',
            dipv6='de:ad:be:ef::2',
            nh=17)
        pkt1 = udpv6_inner1.get_packet()
        self.assertIsNotNone(pkt1)
        mpls = MplsoUdpPacket(
            label=48,
            sip='1.1.2.2',
            dip='2.2.1.1',
            smac='de:ad:be:ef:00:01',
            dmac='de:ad:be:ef:00:02',
            sport=257,
            dport=6635,
            inner_pkt=pkt1)
        pkt = mpls.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        udpv6_inner2 = Udpv6Packet(
            sport=27648,
            dport=256,
            sipv6='de:ad:be:ef::1',
            dipv6='de:ad:be:ef::2',
            smac='de:ad:be:ef:00:01',
            dmac='de:ad:be:ef:00:02',
            nh=17)
        pkt2 = udpv6_inner2.get_packet()
        self.assertIsNotNone(pkt2)
        vxlan = VxlanPacket(
            vnid=0x32,
            sip='1.1.2.2',
            dip='2.2.1.1',
            smac='de:ad:be:ef:00:01',
            dmac='de:ad:be:ef:00:02',
            sport=4789,
            dport=4789,
            flags=0x08,
            reserved1=0x00,
            nxt_protocol=0,
            inner_pkt=pkt2)
        exp_pkt = vxlan.get_packet()
        exp_pkt.show()
        self.assertIsNotNone(exp_pkt)

        rcv_pkt = fabric_interface1.send_and_receive_packet(
            pkt, fabric_interface2, exp_pkt)
        # check if we got IPv6 packet
        self.assertTrue(IPv6 in rcv_pkt[0])

        # Check if the packet was received at fabric_interface1
        self.assertEqual(1, fabric_interface2.get_vif_opackets())
