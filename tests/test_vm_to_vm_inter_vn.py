#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

# anything with *test* will be assumed by pytest as a test


class TestVmToVmInterVn(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()
        ObjectBase.set_auto_features(cleanup=True)

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)

        # Add tenant vif3
        self.vif3 = VirtualVif(
            idx=3,
            name="tap88670c2e-11",
            ipv4_str="1.1.1.4",
            mac_str="00:00:5e:00:01:00",
            vrf=3,
            mcast_vrf=3,
            nh_idx=23)

        # Add tenant vif4
        self.vif4 = VirtualVif(
            idx=4,
            name="tape703ea67-f1",
            ipv4_str="2.2.2.4",
            mac_str="00:00:5e:00:01:00",
            vrf=4,
            mcast_vrf=4,
            nh_idx=28)

        # Add vif3 encap nexthop (inet)
        self.vif3_nh = EncapNextHop(
            encap_oif_id=self.vif3.idx(),
            encap="02 88 67 0c 2e 11 00 00 5e 00 01 00 08 00",
            nh_vrf=3,
            nh_idx=23,
            nh_flags=(
                constants.NH_FLAG_POLICY_ENABLED |
                constants.NH_FLAG_ETREE_ROOT))

        # Add vif4 encap nexthop (inet)
        self.vif4_nh = EncapNextHop(
            encap_oif_id=self.vif4.idx(),
            encap="02 e7 03 ea 67 f1 00 00 5e 00 01 00 08 00",
            nh_vrf=4,
            nh_idx=28,
            nh_flags=(
                constants.NH_FLAG_POLICY_ENABLED |
                constants.NH_FLAG_ETREE_ROOT))

        # Add overlay L2 Receive NH
        self.l2_nh = ReceiveL2NextHop(
            nh_idx=3,
            nh_flags=constants.NH_FLAG_ETREE_ROOT)

        # Add vif3 bridge Route with agent MAC
        self.vif3_bridge_route = BridgeRoute(
            nh_idx=3, vrf=3, mac_str="00:00:5e:00:01:00")

        # Add vif4 bridge Route with agent MAC
        self.vif4_bridge_route = BridgeRoute(
            nh_idx=3, vrf=4, mac_str="00:00:5e:00:01:00")

        # Add vif3 Route (note this is vif4's subnet route)
        self.vif3_inet_route = InetRoute(
            prefix="2.2.2.4",
            vrf=3,
            nh_idx=28)

        # Add vif4 Route (note this is vif3's subnet route)
        self.vif4_inet_route = InetRoute(
            prefix="1.1.1.4",
            vrf=4,
            nh_idx=23)

        ObjectBase.sync_all()

        # Add forward and reverse flow
        self.f_flow = InetFlow(
            sip='1.1.1.4',
            dip='2.2.2.4',
            sport=1136,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flow_nh_idx=23,
            src_nh_idx=23,
            flow_vrf=3,
            rflow_nh_idx=28)

        self.r_flow = InetFlow(
            sip='2.2.2.4',
            dip='1.1.1.4',
            sport=1136,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flow_nh_idx=28,
            flags=constants.VR_RFLOW_VALID,
            src_nh_idx=28,
            flow_vrf=4,
            rflow_nh_idx=23)
        self.f_flow.sync_and_link_flow(self.r_flow)
        self.assertGreater(self.f_flow.get_fr_index(), 0)

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def test_vm_to_vm_inter_vn(self):

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
        rec_pkt = self.vif3.send_and_receive_packet(pkt, self.vif4, pkt)
        # check if we got ICMP packet
        self.assertTrue(ICMP in rec_pkt)
        self.assertEqual('02:88:67:0c:2e:11', rec_pkt.src)
        self.assertEqual('00:00:5e:00:01:00', rec_pkt.dst)

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
        rec_pkt = self.vif4.send_and_receive_packet(pkt, self.vif3, pkt)
        # check if we got ICMP packet
        self.assertTrue(ICMP in rec_pkt)
        self.assertEqual('02:e7:03:ea:67:f1', rec_pkt.src)
        self.assertEqual('00:00:5e:00:01:00', rec_pkt.dst)

        # Check if the packet was received at vif3 and vif4
        self.assertEqual(1, self.vif3.get_vif_opackets())
        self.assertEqual(1, self.vif3.get_vif_ipackets())

        self.assertEqual(1, self.vif4.get_vif_opackets())
        self.assertEqual(1, self.vif4.get_vif_ipackets())

    def test_hbs_vm_to_vm_inter_vn(self):

        # Add hbs-l vif
        hbs_l_vif = VirtualVif(
            name="tap1589a2b3-22",
            ipv4_str="100.100.100.4",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=3,
            flags=constants.VIF_FLAG_HBS_LEFT)
        hbs_l_vif.sync()

        # Add hbs-r vif
        hbs_r_vif = VirtualVif(
            name="tap8b05a86b-36",
            ipv4_str="200.200.200.4",
            mac_str="00:00:5e:00:01:00",
            idx=6,
            vrf=4,
            flags=constants.VIF_FLAG_HBS_RIGHT)
        hbs_r_vif.sync()

        # Add vif3 Nexthop (bridge)
        # pkt from hbs-r to vif 3 will need a lookup of dst-mac
        # in the bridge table
        # this is because dmac would have been encoded with flow id
        vif3_nhb = EncapNextHop(
            encap_oif_id=self.vif3.idx(),
            encap="02 88 67 0c 2e 11 00 00 5e 00 01 00 08 00",
            nh_idx=27,
            nh_family=constants.AF_BRIDGE,
            nh_vrf=3,
            nh_flags=constants.NH_FLAG_POLICY_ENABLED |
            constants.NH_FLAG_ETREE_ROOT)
        vif3_nhb.sync()

        # Add bridge Route
        bridge_route = BridgeRoute(
            vrf=3,
            mac_str="02:88:67:0c:2e:11",
            nh_idx=27)
        bridge_route.sync()

        # Add hbs-l and hbs-r in the vrf table
        vrf = Vrf(
            vrf_rid=0,
            vrf_idx=3,
            vrf_flags=constants.VRF_FLAG_VALID |
            constants.VRF_FLAG_HBS_L_VALID |
            constants.VRF_FLAG_HBS_R_VALID,
            vrf_hbfl_vif_idx=5,
            vrf_hbfr_vif_idx=6)
        vrf.sync()

        # Add hbs-l and hbs-r in the vrf table
        vrf = Vrf(
            vrf_rid=0,
            vrf_idx=4,
            vrf_flags=constants.VRF_FLAG_VALID |
            constants.VRF_FLAG_HBS_L_VALID |
            constants.VRF_FLAG_HBS_R_VALID,
            vrf_hbfl_vif_idx=5,
            vrf_hbfr_vif_idx=6)
        vrf.sync()

        self.f_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_LEFT
        self.r_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_RIGHT
        self.f_flow.sync()
        self.r_flow.sync()

        # send ping request from vif3 and receive in hbs-l
        icmp = IcmpPacket(
            sip='1.1.1.4',
            dip='2.2.2.4',
            smac='02:88:67:0c:2e:11',
            dmac='00:00:5e:00:01:00',
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet
        rcv_pkt = self.vif3.send_and_receive_packet(pkt, hbs_l_vif, pkt)

        # send encoded packet from hbs-r and receive on tenant_vif4
        icmp = IcmpPacket(
            sip='1.1.1.4',
            dip='2.2.2.4',
            smac='ca:f1:00:00:a9:4c',
            dmac='00:00:5e:00:01:00',
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # send packet
        rcv_pkt = hbs_r_vif.send_and_receive_packet(pkt, self.vif4, pkt)

        # send ping response from tenant_vif4 and receive in hbs-r
        icmp = IcmpPacket(
            sip='2.2.2.4',
            dip='1.1.1.4',
            smac='02:e7:03:ea:67:f1',
            dmac='00:00:5e:00:01:00',
            icmp_type=constants.ECHO_REPLY,
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # send packet
        rcv_pkt = self.vif4.send_and_receive_packet(pkt, hbs_r_vif, pkt)

        # send ping response from hbs-r and receive in tenant_vif3
        icmp = IcmpPacket(
            sip='2.2.2.4',
            dip='1.1.1.4',
            smac='00:00:5e:00:01:00',
            dmac='c0:d1:00:04:05:8c',
            icmp_type=constants.ECHO_REPLY,
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # send packet
        rcv_pkt = hbs_l_vif.send_and_receive_packet(pkt, self.vif3, pkt)

        # Check if the packet was sent on tenant_vif3 and received at hbs-l
        self.assertEqual(1, self.vif3.get_vif_ipackets())
        self.assertEqual(1, hbs_l_vif.get_vif_opackets())

        # Check if the packet was sent to hbs-r and received from tenant_vif4
        self.assertEqual(1, hbs_r_vif.get_vif_opackets())
        self.assertEqual(1, self.vif4.get_vif_ipackets())

        # Check if the packet was sent on tenant_vif4 and received at hbs-r
        self.assertEqual(1, self.vif4.get_vif_opackets())
        self.assertEqual(1, hbs_r_vif.get_vif_ipackets())

        # Check if the packet was sent to hbs-l and received from tenant_vif3
        self.assertEqual(1, hbs_l_vif.get_vif_opackets())
        self.assertEqual(1, self.vif3.get_vif_ipackets())
