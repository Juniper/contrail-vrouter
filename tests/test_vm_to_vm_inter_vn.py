#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from vtest_imports import *


# anything with *test* will be assumed by pytest as a test

class TestVmToVmInterVn(unittest.TestCase, vtest_common.VTestCommon):

    @classmethod
    def setup_class(cls):
        VTestObjectBase.setUpClass()
        VTestObjectBase.set_auto_features(cleanup=True)

    @classmethod
    def teardown_class(cls):
        VTestObjectBase.tearDownClass()

    def setup_method(self, method):
        VTestObjectBase.setUp(method)

    def teardown_method(self, method):
        VTestObjectBase.tearDown()

    def test_vm_to_vm_inter_vn(self):

        # Add tenant vif3
        vif3 = VirtualVif(
            idx=3,
            name="tap88670c2e-11",
            ipv4_str="1.1.1.4",
            mac_str="00:00:5e:00:01:00",
            vrf=3,
            mcast_vrf=3,
            nh_id=23)

        # Add tenant vif4
        vif4 = VirtualVif(
            idx=4,
            name="tape703ea67-f1",
            ipv4_str="2.2.2.4",
            mac_str="00:00:5e:00:01:00",
            vrf=4,
            mcast_vrf=4,
            nh_id=28)

        # Add vif3 encap nexthop (inet)
        vif3_nh = EncapNextHop(
            encap_oif_id=vif3.idx(),
            encap="02 88 67 0c 2e 11 00 00 5e 00 01 00 08 00",
            nh_vrf=3,
            nh_id=23,
            nh_flags=(
                vtconst.NH_FLAG_VALID | vtconst.NH_FLAG_POLICY_ENABLED | \
                        vtconst.NH_FLAG_ETREE_ROOT))

        # Add vif4 encap nexthop (inet)
        vif4_nh = EncapNextHop(
            encap_oif_id=vif4.idx(),
            encap="02 e7 03 ea 67 f1 00 00 5e 00 01 00 08 00",
            nh_vrf=4,
            nh_id=28,
            nh_flags=(
                vtconst.NH_FLAG_VALID | vtconst.NH_FLAG_POLICY_ENABLED | \
                        vtconst.NH_FLAG_ETREE_ROOT))

        # Add overlay L2 Receive NH
        l2_nh = ReceiveL2NextHop(nh_id=3, nh_vrf=0, nh_flags=(
            vtconst.NH_FLAG_VALID | vtconst.NH_FLAG_ETREE_ROOT))

        # Add vif3 bridge Route with agent MAC
        vif3_bridge_route = BridgeRoute(
            nh_id=3, vrf=3, mac_str="00:00:5e:00:01:00")

        # Add vif4 bridge Route with agent MAC
        vif4_bridge_route = BridgeRoute(
            nh_id=3, vrf=4, mac_str="00:00:5e:00:01:00")

        # Add vif3 Route (note this is vif4's subnet route)
        vif3_inet_route = InetRoute(
            prefix="2.2.2.4",
            vrf=3,
            nh_id=28,
            rtr_label_flags=vtconst.VR_RT_ARP_PROXY_FLAG)

        # Add vif4 Route (note this is vif3's subnet route)
        vif4_inet_route = InetRoute(
            prefix="1.1.1.4",
            vrf=4,
            nh_id=23,
            rtr_label_flags=vtconst.VR_RT_ARP_PROXY_FLAG)
        VTestObjectBase.sync_all()

        # Add forward and reverse flow and link them
        f_flow = InetFlow(sip='1.1.1.4', dip='2.2.2.4', sport=1136, dport=0,
                          proto=vtconst.VR_IP_PROTO_ICMP, flow_nh_id=23,
                          src_nh_idx=23, flow_vrf=3, rflow_nh_id=28)
        r_flow = InetFlow(sip='2.2.2.4', dip='1.1.1.4', sport=1136, dport=0,
                          proto=vtconst.VR_IP_PROTO_ICMP, flow_nh_id=28,
                          src_nh_idx=28, flow_vrf=4, rflow_nh_id=23)
        f_flow.sync_and_link_flow(r_flow)
        self.assertGreater(f_flow.get_fr_index(), 0)

        # send ping request from vif3
        icmp = IcmpPacket(
            sip='1.1.1.4',
            dip='2.2.2.4',
            smac='02:88:67:0c:2e:11',
            dmac='00:00:5e:00:01:00',
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet
        rec_pkt = vif3.send_and_receive_packet(pkt, vif4, pkt)
        # check if we got ICMP packet
        self.assertTrue(ICMP in rec_pkt[0])

        # send ping request from vif4
        icmp = IcmpPacket(
            sip='2.2.2.4',
            dip='1.1.1.4',
            smac='02:e7:03:ea:67:f1',
            dmac='00:00:5e:00:01:00',
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet
        rec_pkt = vif4.send_and_receive_packet(pkt, vif3, pkt)
        # check if we got ICMP packet
        self.assertTrue(ICMP in rec_pkt[0])

        # Check if the packet was received at vif3 and vif4
        self.assertEqual(1, vif3.get_vif_opackets())
        self.assertEqual(1, vif3.get_vif_ipackets())

        self.assertEqual(1, vif4.get_vif_opackets())
        self.assertEqual(1, vif4.get_vif_ipackets())
