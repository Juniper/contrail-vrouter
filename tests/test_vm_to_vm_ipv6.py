#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

# anything with *test* will be assumed by pytest as a test


class TestVmToVmIPv6(unittest.TestCase):

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

    def test_vm_to_vm_ipv6(self):

        vif1 = VirtualVif(
            name="tap_1",
            idx=1,
            ipv4_str=None,
            mac_str="de:ad:be:ef:00:02",
            flags=None)

        vif2 = VirtualVif(
            name="tap_2",
            idx=2,
            ipv4_str=None,
            mac_str="de:ad:be:ef:00:01",
            flags=None)

        nh = EncapNextHop(
            encap_oif_id=vif2.idx(),
            encap="de ad be ef 00 01 de ad be ef 00 02 08 00",
            nh_idx=12,
            nh_family=constants.AF_BRIDGE)

        bridge_route = BridgeRoute(
            vrf=0,
            mac_str="de:ad:be:ef:00:01",
            nh_idx=12)
        ObjectBase.sync_all()

        udp = Udpv6Packet(
            sipv6="de:ad:be:ef::1",
            dipv6="de:ad:be:ef::2",
            smac="de:ad:be:ef:00:02",
            dmac="de:ad:be:ef:00:01",
            sport=0,
            dport=1)
        pkt = udp.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        rec_pkt = vif1.send_and_receive_packet(pkt, vif2)

        self.assertTrue(IPv6 in rec_pkt)
        self.assertEqual('de:ad:be:ef::1', rec_pkt[IPv6].src)
        self.assertEqual('de:ad:be:ef::2', rec_pkt[IPv6].dst)

        self.assertEqual(1, vif1.get_vif_ipackets())
        self.assertEqual(1, vif2.get_vif_opackets())
