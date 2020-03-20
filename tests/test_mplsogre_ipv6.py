#!/us/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

# anything with *test* will be assumed by pytest as a test


class TestMplsoGREv6(unittest.TestCase):

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

    def test_mplsogre_v6_bridge(self):

        vif1 = VirtualVif(
            name="tap_1",
            idx=1,
            ipv4_str=None,
            mac_str="de:ad:be:ef:00:02",
            flags=None,
            mtu=2514)

        vif2 = VirtualVif(
            name="tap_2",
            idx=2,
            ipv4_str=None,
            mac_str="de:ad:be:ef:00:01",
            flags=None,
            mtu=2514)

        nh_tunnel = TunnelNextHopV4(
            encap_oif_id=vif2.idx(),
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

        udp = Udpv6Packet(
            sipv6="de:ad:be:ef::1",
            dipv6="de:ad:be:ef::2",
            smac="de:ad:be:ef:00:02",
            dmac="de:ad:be:ef:00:01",
            sport=0,
            dport=1)
        pkt1 = udp.get_packet()
        pkt1.show()
        self.assertIsNotNone(pkt1)

        mplsogre = MplsoGrePacket(
            label=128,
            sip="1.1.2.2",
            dip="2.2.1.1",
            smac="00:11:11:11:11:11",
            dmac="00:22:22:22:22:22")
        pkt2 = mplsogre.get_packet()
        pkt2.show()
        self.assertIsNotNone(pkt2)

        rec_pkt = vif1.send_and_receive_packet(pkt1, vif2, pkt2)

        self.assertEqual(1, vif1.get_vif_ipackets())
        self.assertEqual(1, vif2.get_vif_opackets())
