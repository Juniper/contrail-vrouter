#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

# anything with *test* will be assumed by pytest as a test


class TestFabricToVmiInterVn(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()
        ObjectBase.set_auto_features(cleanup=True)

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)

        # Add fabric interface
        self.fabric_interface = FabricVif(
            name="eth1",
            mac_str="00:1b:21:bb:f9:48")

        # Add vhost0 vif
        self.vhost0_vif = VhostVif(
            ipv4_str="8.0.0.2",
            mac_str="00:1b:21:bb:f9:48",
            idx=1)

        # Add agent vif
        self.agent_vif = AgentVif(idx=2)

        # Add tenant vif
        self.tenant_vif = VirtualVif(
            name="tapc2234cd0-55",
            ipv4_str="1.1.1.3",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=5,
            mcast_vrf=5,
            nh_idx=38)

        # Add vif Nexthop
        self.vif_nh = EncapNextHop(
            encap_oif_id=self.tenant_vif.idx(),
            encap="02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00",
            nh_idx=38,
            nh_vrf=5,
            nh_flags=constants.NH_FLAG_POLICY_ENABLED |
            constants.NH_FLAG_ETREE_ROOT)

        # Add underlay Receive NH
        self.underlay_rnh = ReceiveNextHop(
            encap_oif_id=self.vhost0_vif.idx(),
            nh_idx=10,
            nh_vrf=1,
            nh_flags=constants.NH_FLAG_RELAXED_POLICY |
            constants.NH_FLAG_ETREE_ROOT)

        # Add underlay Route
        self.underlay_route = InetRoute(
            vrf=0,
            prefix="8.0.0.2",
            nh_idx=10,
            rtr_label_flags=constants.VR_RT_ARP_TRAP_FLAG)

        # Add Encap L2 Nexthop for overlay
        self.l2_nh = EncapNextHop(
            encap_oif_id=self.tenant_vif.idx(),
            encap="02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00",
            nh_idx=44,
            nh_family=constants.AF_BRIDGE,
            nh_vrf=5,
            nh_flags=constants.NH_FLAG_POLICY_ENABLED |
            constants.NH_FLAG_ETREE_ROOT)

        # Add Bridge Route
        self.bridge_route = BridgeRoute(
            vrf=5,
            mac_str="02:c2:23:4c:d0:55",
            nh_idx=44)

        # Add MPLS entry for overlay
        self.mpls_entry = Mpls(
            mr_label=42,
            mr_nhid=38)

        # Add tunnel NH (for src validation)
        self.tunnel_nh = TunnelNextHopV4(
            encap_oif_id=self.fabric_interface.idx(),
            encap="00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00",
            tun_sip="8.0.0.2",
            tun_dip="8.0.0.3",
            nh_idx=21,
            nh_flags=constants.NH_FLAG_TUNNEL_UDP_MPLS |
            constants.NH_FLAG_ETREE_ROOT)
        ObjectBase.sync_all()

        # Add forward and reverse flow
        self.f_flow = InetFlow(
            sip='1.1.1.3',
            dip='2.2.2.3',
            sport=4145,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flow_nh_idx=38,
            src_nh_idx=38,
            flow_vrf=5,
            rflow_nh_idx=21)

        self.r_flow = InetFlow(
            sip='2.2.2.3',
            dip='1.1.1.3',
            sport=4145,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flow_nh_idx=38,
            flags=constants.VR_RFLOW_VALID,
            src_nh_idx=21,
            flow_vrf=5,
            rflow_nh_idx=21)
        self.f_flow.sync_and_link_flow(self.r_flow)
        self.assertGreater(self.f_flow.get_fr_index(), 0)

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def test_fabric_to_vm_inter_vn(self):

        # send mplsudp packet from fabric
        icmp_inner = IcmpPacket(
            sip='2.2.2.3',
            dip='1.1.1.3',
            icmp_type=constants.ECHO_REPLY,
            id=4145)
        pkt = icmp_inner.get_packet()
        self.assertIsNotNone(pkt)

        mpls = MplsoUdpPacket(
            label=42,
            sip='8.0.0.3',
            dip='8.0.0.2',
            smac='00:1b:21:bb:f9:46',
            dmac='00:1b:21:bb:f9:48',
            sport=53363,
            dport=6635,
            inner_pkt=pkt)
        pkt = mpls.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # Make sure the packet comes goes to hbf-r (tap8b05a86b-36)
        rcv_pkt = self.fabric_interface.send_and_receive_packet(
            pkt, self.tenant_vif)

        # check if decapsulated packet is received at tenant vif
        self.assertEqual('2.2.2.3', rcv_pkt[IP].src)
        self.assertEqual('1.1.1.3', rcv_pkt[IP].dst)

        # Check if the packet was sent to vrouter (by vtest) on fabric
        # and received at tenant_vif (by vtest)
        self.assertEqual(1, self.fabric_interface.get_vif_ipackets())
        self.assertEqual(1, self.tenant_vif.get_vif_opackets())

    def test_hbs_fabric_to_vmi_inter_vn(self):

        # Add hbs-l vif
        hbs_l_vif = VirtualVif(
            name="tap1589a2b3-22",
            ipv4_str="100.100.100.4",
            mac_str="00:00:5e:00:01:00",
            idx=3,
            vrf=3,
            flags=constants.VIF_FLAG_HBS_LEFT)
        hbs_l_vif.sync()

        # Add hbs-r vif
        hbs_r_vif = VirtualVif(
            name="tap8b05a86b-36",
            ipv4_str="200.200.200.4",
            mac_str="00:00:5e:00:01:00",
            idx=4,
            vrf=4,
            flags=constants.VIF_FLAG_HBS_RIGHT)
        hbs_r_vif.sync()

        # Add hbs-l and hbs-r in the vrf table
        vrf = Vrf(
            vrf_rid=0,
            vrf_idx=5,
            vrf_flags=constants.VRF_FLAG_VALID |
            constants.VRF_FLAG_HBS_L_VALID |
            constants.VRF_FLAG_HBS_R_VALID,
            vrf_hbfl_vif_idx=3,
            vrf_hbfr_vif_idx=4)
        vrf.sync()

        self.f_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_LEFT
        self.r_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_RIGHT
        self.f_flow.sync()
        self.r_flow.sync()

        # send mplsudp packet from fabric
        icmp_inner = IcmpPacket(
            sip='2.2.2.3',
            dip='1.1.1.3',
            icmp_type=constants.ECHO_REPLY,
            id=4145)
        pkt = icmp_inner.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)
        mpls = MplsoUdpPacket(
            label=42,
            sip='8.0.0.3',
            dip='8.0.0.2',
            smac='00:1b:21:bb:f9:46',
            dmac='00:1b:21:bb:f9:48',
            sport=53363,
            dport=6635,
            id=10,
            inner_pkt=pkt)
        pkt = mpls.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # Make sure the packet comes goes to hbs-r (tap8b05a86b-36)
        rcv_pkt = self.fabric_interface.send_and_receive_packet(
            pkt, hbs_r_vif)

        # TODO: Send the rcv_pkt to the next call instead of
        #       forming a new packet
        # Inject the packet from hbs-l to vrouter
        # Encode the flow id in the dst mac of the packet
        icmp = IcmpPacket(
            sip='1.0.0.5',
            dip='1.0.0.3',
            smac='00:00:5e:00:01:00',
            dmac='c0:d2:00:06:08:f0',
            icmp_type=0,
            id=4145)
        pkt = icmp.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # Send it to hbs-l
        rcv_pkt = hbs_l_vif.send_and_receive_packet(pkt, self.tenant_vif)

        # Check if the packet was sent to vrouter (by vtest) on fabric
        # and received at tenant_vif (by vtest)
        self.assertEqual(1, self.fabric_interface.get_vif_ipackets())
        self.assertEqual(1, self.tenant_vif.get_vif_opackets())

        # Check if the packet was sent to hbs-r (by vrouter)
        # and received at hbs-l (by vtest)
        self.assertEqual(1, hbs_r_vif.get_vif_opackets())
        self.assertEqual(1, hbs_l_vif.get_vif_ipackets())
