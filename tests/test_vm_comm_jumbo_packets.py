#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

# anything with *test* will be assumed by pytest as a test


class TestVmCommJumboPackets(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()
        ObjectBase.set_auto_features(cleanup=True)

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)

    def test_vm_comm_jumbo_packets(self):

        vif1 = VirtualVif(
            name="tap_1",
            idx=1,
            ipv4_str=None,
            mac_str="de:ad:be:ef:00:02",
            mtu=9014,
            flags=None)

        vif2 = VirtualVif(
            name="tap_2",
            idx=2,
            ipv4_str=None,
            mac_str="de:ad:be:ef:00:01",
            mtu=9014)

        nh = EncapNextHop(
            encap_oif_id=vif2.idx(),
            encap="de ad be ef 00 01 de ad be ef 00 02 08 00",
            nh_idx=12,
            nh_family=constants.AF_BRIDGE)

        route = BridgeRoute(
            vrf=0,
            mac_str="de:ad:be:ef:00:01",
            nh_idx=12)

        ObjectBase.sync_all()

        udp = UdpPacket(
            sip="1.1.1.1",
            dip="2.2.2.2",
            sport=7936,
            dport=7936,
            smac="de:ad:be:ef:00:02",
            dmac="de:ad:be:ef:00:01",
            jumbo=True)
        pkt = udp.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # send packet
        rec_pkt = vif1.send_and_receive_packet(pkt, vif2)

        # check if we got UDP packet
        self.assertTrue(UDP in rec_pkt)
        self.assertEqual("de:ad:be:ef:00:02", rec_pkt.src)
        self.assertEqual("de:ad:be:ef:00:01", rec_pkt.dst)

        # Check if the packet was received at vif1
        self.assertEqual(1, vif1.get_vif_ipackets())
        self.assertEqual(1, vif2.get_vif_opackets())
