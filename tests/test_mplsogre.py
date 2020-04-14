#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

# anything with *test* will be assumed by pytest as a test


class TestMplsoGre(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()
        ObjectBase.set_auto_features(cleanup=True)

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)

        self.vif1 = VirtualVif(
            name="tap_1",
            idx=1,
            ipv4_str=None,
            mac_str="de:ad:be:ef:00:02",
            mtu=2514,
            flags=None)

        self.vif2 = VirtualVif(
            name="tap_2",
            idx=2,
            ipv4_str=None,
            mac_str="de:ad:be:ef:00:01",
            mtu=2514,
            flags=None)

        ObjectBase.sync_all()

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def test_mplsogre_bridge(self):

        nh_tunnel = TunnelNextHopV4(
            encap_oif_id=self.vif2.idx(),
            encap="00 22 22 22 22 22 00 11 11 11 11 11 08 00",
            tun_sip="1.1.2.2",
            tun_dip="2.2.1.1",
            nh_idx=12,
            nh_flags=constants.NH_FLAG_TUNNEL_GRE)

        bridge_route = BridgeRoute(
            vrf=0,
            mac_str="de:ad:be:ef:00:01",
            nh_idx=12,
            rtr_label=128,
            rtr_label_flags=3)

        ObjectBase.sync_all()

        udp = UdpPacket(
            sip="1.1.1.1",
            dip="2.2.2.2",
            smac="de:ad:be:ef:00:02",
            dmac="de:ad:be:ef:00:01",
            sport=0,
            dport=1)
        pkt1 = udp.get_packet()
        pkt1.show()
        self.assertIsNotNone(pkt1)

        rec_pkt = self.vif1.send_and_receive_packet(pkt1, self.vif2)

        # Check if the rcv pkt contains mplsogre header
        self.assertTrue((GRE in rec_pkt) and (rec_pkt[GRE].proto == 34887))

        self.assertEqual(1, self.vif1.get_vif_ipackets())
        self.assertEqual(1, self.vif2.get_vif_opackets())

    def test_mplsogre_route(self):

        nh_tunnel = TunnelNextHopV4(
            encap_oif_id=self.vif2.idx(),
            encap="de ad be ef 00 01 de ad be ef 00 02 08 00",
            tun_sip="1.1.2.2",
            tun_dip="2.2.1.1",
            nh_idx=12,
            nh_flags=constants.NH_FLAG_TUNNEL_GRE)

        inet_route = InetRoute(
            vrf=0,
            prefix="2.2.2.2",
            nh_idx=12,
            rtr_label=48,
            rtr_label_flags=1)

        nh_l2rcv = ReceiveL2NextHop(
            nh_idx=13,
            nh_family=0)

        bridge_route = BridgeRoute(
            vrf=0,
            mac_str="de:ad:be:ef:00:01",
            nh_idx=13,
            rtr_label_flags=0)

        ObjectBase.sync_all()

        udp = UdpPacket(
            sip="1.1.1.1",
            dip="2.2.2.2",
            smac="de:ad:be:ef:00:02",
            dmac="de:ad:be:ef:00:01",
            sport=7936,
            dport=7936)
        pkt1 = udp.get_packet()
        pkt1.show()
        self.assertIsNotNone(pkt1)

        udp_inner = UdpPacket(
            sip="1.1.1.1",
            dip="2.2.2.2",
            sport=7936,
            dport=7936)
        inner_pkt = udp_inner.get_packet()

        rec_pkt = self.vif1.send_and_receive_packet(pkt1, self.vif2)

        # Check if the rcv pkt contains mplsogre header
        self.assertTrue((GRE in rec_pkt) and (rec_pkt[GRE].proto == 34887))

        self.assertEqual(1, self.vif1.get_vif_ipackets())
        self.assertEqual(1, self.vif2.get_vif_opackets())
