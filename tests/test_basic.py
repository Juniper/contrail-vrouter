#!/usr/bin/python
import os
import sys
import unittest
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from dropstats import *
import vtest_common
from flow import *
from route import *
from nexthop import *
from vif import *
from packet import *
import vtconst


# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test

class TestBasic(unittest.TestCase, vtest_common.VTestCommon):

    @classmethod
    def setup_class(cls):
        VTestObjectBase.setUpClass()
        VTestObjectBase.auto_cleanup = True
        VTestCommon.vif_auto_alloc = True
        VTestCommon.nh_auto_alloc = True

    @classmethod
    def teardown_class(cls):
        VTestObjectBase.tearDownClass()

    def setup_method(self, method):
        VTestObjectBase.setUp(method)

    def teardown_method(self, method):
        VTestObjectBase.tearDown()

    def test_vif(self):
        vif = VirtualVif(name="tap_1", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02")

        vif.sync()
        self.assertIn("tap_1", vif.get_vif_name())

    def test_vif_v6(self):
        vmi = VirtualVif(name="tap_2", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02",
                         ip6_u=72340172838076673, ip6_l=18374403900871474942)
        vmi.sync()
        self.assertIn("tap_2", vmi.get_vif_name())

    def test_encap_nh(self):
        # add the virtual vif
        vif = VirtualVif(name="tap_3", ipv4_str="1.1.1.10",
                         mac_str="de:ad:be:ef:00:02")

        # add encap nexthop
        nh = EncapNextHop(encap_oif_id=vif.idx(),
                          encap="de ad be ef 00 02 de ad be ef 00 01 08 00")
        # sync all objects
        VTestObjectBase.sync_all()

        # check if virtual vif and encap nh got added
        self.assertIn("tap_3", vif.get_vif_name())
        self.assertEqual(nh.id(), nh.get_nh_id())

    def test_tunnel_nh(self):
        # add fabric vif
        vmi = FabricVif(name="en0", ipv4_str="192.168.1.1",
                        mac_str="de:ad:be:ef:00:02")

        # add tunnel nh
        nh = TunnelNextHopV4(
            encap_oif_id=vmi.idx(),
            encap="de ad be ef 00 02 de ad be ef 00 01 08 00",
            tun_sip="1.1.1.1",
            tun_dip="1.1.1.2",
            nh_flags=(
                vtconst.NH_FLAG_VALID | vtconst.NH_FLAG_TUNNEL_VXLAN))
        VTestObjectBase.sync_all()

        # check if fabric vif and tunnel nh got added
        self.assertIn("en0", vmi.get_vif_name())
        self.assertEqual(nh.id(), nh.get_nh_id())

    def test_rt(self):
        # add virtual vif
        vmi = VirtualVif(name="tap_5", ipv4_str="192.168.1.1",
                         mac_str="de:ad:be:ef:00:02")
        # add encap nh 1
        nh1 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00",
                           nh_family=vtconst.AF_BRIDGE)
        # add encap nh 2
        nh2 = EncapNextHop(encap_oif_id=vmi.idx(),
                           encap="de ad be ef 00 02 de ad be ef 00 01 08 00")
        # add bridge route
        bridge_rt = BridgeRoute(vrf=0, mac="de:ad:be:ef:00:02", nh_id=nh1.id())
        # add inet route
        inet_rt = InetRoute(
            vrf=0,
            prefix="192.168.1.1",
            prefix_len=32,
            nh_id=nh2.id())
        # sync all objects
        VTestObjectBase.sync_all()

        # Query the objects back
        bridge_rt.rtr_nh_id = 0
        bridge_rt.rtr_index = -1
        self.assertIn("tap_5", vmi.get_vif_name())
        self.assertEqual(nh1.id(), nh1.get_nh_id())
        self.assertEqual(nh2.id(), nh2.get_nh_id())
        self.assertEqual(nh1.id(), bridge_rt.get_rtr_nh_id())
        self.assertEqual(nh2.id(), inet_rt.get_rtr_nh_id())

    def test_flow(self):
        flow1 = InetFlow(sip='1.1.1.4', dip='2.2.2.4', sport=1136, dport=0,
                         proto=vtconst.VR_IP_PROTO_ICMP, flow_nh_id=23,
                         src_nh_idx=23, flow_vrf=3, rflow_nh_id=28)
        flow1.sync(resp_required=True)
        self.assertGreater(flow1.get_fr_index(), 0)

    def test_flow_sync_and_add_reverse_flow(self):
        flow1 = InetFlow(sip='1.1.1.5', dip='2.2.2.5', sport=1136, dport=0,
                         proto=vtconst.VR_IP_PROTO_ICMP, flow_nh_id=23,
                         src_nh_idx=23, flow_vrf=3, rflow_nh_id=28)
        flow1.sync_and_add_reverse_flow()
        self.assertGreater(flow1.get_fr_index(), 0)

    def test_dropstats(self):
        # add virtual vif
        vmi = VirtualVif(
            name="tap_10",
            ipv4_str="1.1.1.10",
            mac_str="de:ad:be:ef:00:02")
        vmi.sync()
        self.assertIn("tap_10", vmi.get_vif_name())

        # create an invalid unicast ARP pkt which should get dropped in vrouter
        arp = ArpPacket("de:ad:be:ef:00:02", "de:ad:be:ef:00:00", 1, 0x1, 7)
        pkt = arp.get_packet()
        pkt.show()

        vmi.send_packet(pkt)

        # get the dropstats
        drop_stats = DropStats()
        self.assertIn("1", drop_stats.get("vds_invalid_arp"))

    """
    def test_flow_and_link_flow(self):
        # create flow1
        flow1=InetFlow(sip='1.1.1.4', dip='2.2.2.4', sport=1136, dport=0,
                            proto=vtconst.VR_IP_PROTO_ICMP, flow_nh_id=23,
                            src_nh_idx=23, flow_vrf=3, rflow_nh_id=28)
        flow1.sync(resp_required=True)
        self.assertGreater(flow1.get_fr_index(), 0)
        print("flow1 idx {}".format(flow1.get_fr_index()))

        # create flow2
        flow2 = InetFlow(sip='2.2.2.4', dip='1.1.1.4', sport=1136, dport=0,
                            proto=vtconst.VR_IP_PROTO_ICMP, flow_nh_id=28,
                            src_nh_idx=28, flow_vrf = 3, rflow_nh_id=23)
        flow2.sync(resp_required=True)
        self.assertGreater(flow2.get_fr_index(), 0)
        print("flow2 idx {}".format(flow2.get_fr_index()))

        # link flow1 and flow2
        flow1.link_flow(flow2)
    """
