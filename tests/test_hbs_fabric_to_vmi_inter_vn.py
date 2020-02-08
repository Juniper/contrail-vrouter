#!/usr/bin/python

from imports import *
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')


# anything with *test* will be assumed by pytest as a test

class TestHbsFabricToVmiInterVn(unittest.TestCase):

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

    def test_hbs_fabric_to_vmi_inter_vn(self):

        # Add fabric interface
        fabric_interface = FabricVif(
            name="eth1",
            mac_str="00:1b:21:bb:f9:48",
            idx=0,
            mcast_vrf=65535,
            flags=constants.VIF_FLAG_VHOST_PHYS)
        fabric_interface.sync()

        # Add vhost0 vif
        vhost0_vif = VhostVif(
            ipv4_str="8.0.0.2",
            mac_str="00:1b:21:bb:f9:48",
            idx=1,
            mcast_vrf=65535,
            flags=constants.VIF_FLAG_L3_ENABLED |
            constants.VIF_FLAG_DHCP_ENABLED)
        vhost0_vif.sync()

        # Add agent vif
        agent_vif = AgentVif(
            idx=2,
            flags=constants.VIF_FLAG_L3_ENABLED)
        agent_vif.sync()

        # Add hbs-l vif
        hbs_l_vif = VirtualVif(
            name="tap1589a2b3-22",
            ipv4_str="100.100.100.4",
            mac_str="00:00:5e:00:01:00",
            idx=3,
            vrf=3,
            flags=constants.VIF_FLAG_POLICY_ENABLED |
            constants.VIF_FLAG_HBS_LEFT)
        hbs_l_vif.sync()

        # Add hbs-r vif
        hbs_r_vif = VirtualVif(
            name="tap8b05a86b-36",
            ipv4_str="200.200.200.4",
            mac_str="00:00:5e:00:01:00",
            idx=4,
            vrf=4,
            flags=constants.VIF_FLAG_POLICY_ENABLED |
            constants.VIF_FLAG_HBS_RIGHT)
        hbs_r_vif.sync()

        # Add tenant vif
        tenant_vif = VirtualVif(
            name="tapc2234cd0-55",
            ipv4_str="1.1.1.3",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=5,
            mcast_vrf=5,
            nh_idx=38,
            flags=constants.VIF_FLAG_POLICY_ENABLED |
            constants.VIF_FLAG_DHCP_ENABLED)
        tenant_vif.sync()

        # Add vif Nexthop
        vif_nh = EncapNextHop(
            encap_oif_id=5,
            encap="02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00",
            nh_idx=38,
            nh_vrf=5,
            nh_flags=constants.NH_FLAG_VALID |
            constants.NH_FLAG_POLICY_ENABLED |
            constants.NH_FLAG_ETREE_ROOT)
        vif_nh.sync()

        # Add underlay Receive NH
        underlay_rnh = ReceiveNextHop(
            encap_oif_id=1,
            nh_idx=10,
            nh_vrf=1,
            nh_flags=constants.NH_FLAG_VALID |
            constants.NH_FLAG_RELAXED_POLICY |
            constants.NH_FLAG_ETREE_ROOT)
        underlay_rnh.sync()

        # Add underlay Route
        underlay_route = InetRoute(
            vrf=0,
            prefix="8.0.0.2",
            nh_idx=10,
            rtr_label_flags=constants.VR_RT_ARP_TRAP_FLAG)
        underlay_route.sync()

        # Add Encap L2 Nexthop for overlay
        l2_nh = EncapNextHop(
            encap_oif_id=5,
            encap="02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00",
            nh_idx=44,
            nh_family=constants.AF_BRIDGE,
            nh_vrf=5,
            nh_flags=constants.NH_FLAG_VALID |
            constants.NH_FLAG_POLICY_ENABLED |
            constants.NH_FLAG_ETREE_ROOT)
        l2_nh.sync()

        # Add Bridge Route
        bridge_route = BridgeRoute(
            vrf=5,
            mac_str="02:c2:23:4c:d0:55",
            nh_idx=44)
        bridge_route.sync()

        # Add MPLS entry for overlay
        mpls_entry = Mpls(
            mr_label=42,
            mr_nhid=38,
            mr_rid=0)
        mpls_entry.sync()

        # Add tunnel NH (for src validation)
        tunnel_nh = TunnelNextHopV4(
            encap_oif_id=0,
            encap="00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00",
            tun_sip="8.0.0.2",
            tun_dip="8.0.0.3",
            nh_idx=21,
            nh_flags=constants.NH_FLAG_VALID |
            constants.NH_FLAG_TUNNEL_UDP_MPLS |
            constants.NH_FLAG_ETREE_ROOT)
        tunnel_nh.sync()

        # Add forward and reverse flow and link them
        f_flow = InetFlow(
            sip='1.1.1.3',
            dip='2.2.2.3',
            sport=4145,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flow_nh_idx=38,
            ecmp_nh_index=-1,
            qos_id=-1,
            src_nh_idx=38,
            flow_vrf=5,
            ridx=-1,
            rflow_nh_idx=21,
            flags1=constants.VR_FLOW_FLAG1_HBS_LEFT)
        r_flow = InetFlow(
            sip='2.2.2.3',
            dip='1.1.1.3',
            sport=4145,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flags=4097,
            flow_nh_idx=38,
            ecmp_nh_index=-1,
            qos_id=-1,
            src_nh_idx=21,
            flow_vrf=5,
            rflow_nh_idx=21,
            flags1=constants.VR_FLOW_FLAG1_HBS_RIGHT)
        f_flow.sync_and_link_flow(r_flow)
        self.assertGreater(f_flow.get_fr_index(), 0)

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

        # send mplsudp packet from fabric
        icmp_inner = IcmpPacket(
            sip='2.2.2.3',
            dip='1.1.1.3',
            icmp_type=0,
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
        rcv_pkt = fabric_interface.send_and_receive_packet(pkt, hbs_r_vif, pkt)

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
        rcv_pkt = hbs_l_vif.send_and_receive_packet(pkt, tenant_vif, pkt)

        # Check if the packet was sent to vrouter (by vtest) on fabric
        # and received at tenant_vif (by vtest)
        self.assertEqual(1, fabric_interface.get_vif_ipackets())
        self.assertEqual(1, tenant_vif.get_vif_opackets())

        # Check if the packet was sent to hbs-r (by vrouter)
        # and received at hbs-l (by vtest)
        self.assertEqual(1, hbs_r_vif.get_vif_opackets())
        self.assertEqual(1, hbs_l_vif.get_vif_ipackets())
