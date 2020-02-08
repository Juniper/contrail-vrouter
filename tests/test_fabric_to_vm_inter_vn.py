#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

# anything with *test* will be assumed by pytest as a test


class TestFabricToVmInterVn(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()
        # ObjectBase.set_auto_features(cleanup=True)

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def test_fabric_to_vm_inter_vn(self):

        # Add fabric interface
        fabric_interface = FabricVif(
            name="eth1",
            mac_str="00:1b:21:bb:f9:48",
            idx=0,
            flags=constants.VIF_FLAG_VHOST_PHYS,
            mcast_vrf=65535)

        # Add vhost0 vif
        vhost0_vif = VhostVif(
            ipv4_str="8.0.0.2",
            mac_str="00:1b:21:bb:f9:48",
            idx=1,
            flags=constants.VIF_FLAG_L3_ENABLED |
            constants.VIF_FLAG_DHCP_ENABLED)

        # Add agent vif
        agent_vif = AgentVif(
            idx=2,
            flags=constants.VIF_FLAG_L3_ENABLED)

        # Add tenant vif
        tenant_vif = VirtualVif(
            name="tapc2234cd0-55",
            ipv4_str="1.1.1.3",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=5,
            mcast_vrf=5,
            nh_idx=38)

        # Add vif Nexthop
        vif_nh = EncapNextHop(
            encap_oif_id=5,
            encap="02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00",
            nh_idx=38,
            nh_vrf=5,
            nh_flags=constants.NH_FLAG_VALID |
            constants.NH_FLAG_POLICY_ENABLED |
            constants.NH_FLAG_ETREE_ROOT)

        # Add underlay Receive NH
        underlay_rnh = ReceiveNextHop(
            encap_oif_id=1,
            nh_idx=10,
            nh_vrf=1,
            nh_flags=constants.NH_FLAG_VALID |
            constants.NH_FLAG_RELAXED_POLICY |
            constants.NH_FLAG_ETREE_ROOT)

        # Add underlay Route
        underlay_route = InetRoute(
            vrf=0,
            prefix="8.0.0.2",
            nh_idx=10,
            rtr_label_flags=constants.VR_RT_ARP_TRAP_FLAG)

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

        # Add Bridge Route
        bridge_route = BridgeRoute(
            vrf=5,
            mac_str="02:c2:23:4c:d0:55",
            nh_idx=44)

        # Add MPLS entry for overlay
        mpls_entry = Mpls(
            mr_label=42,
            mr_nhid=38,
            mr_rid=0)

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
        ObjectBase.sync_all()

        # Add forward and reverse flow and link them
        f_flow = InetFlow(sip='1.1.1.3', dip='2.2.2.3', sport=4145, dport=0,
                          proto=constants.VR_IP_PROTO_ICMP, flow_nh_idx=38,
                          ridx=-1, ecmp_nh_index=-1, qos_id=-1, src_nh_idx=38,
                          flow_vrf=5, rflow_nh_idx=21)
        r_flow = InetFlow(
            sip='2.2.2.3',
            dip='1.1.1.3',
            sport=4145,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flow_nh_idx=38,
            flags=constants.VR_FLOW_FLAG_ACTIVE | constants.VR_RFLOW_VALID,
            ridx=-1,
            ecmp_nh_index=-1,
            qos_id=-1,
            src_nh_idx=21,
            flow_vrf=5,
            rflow_nh_idx=21)
        f_flow.sync_and_link_flow(r_flow)
        self.assertGreater(f_flow.get_fr_index(), 0)

        # send mplsudp packet from fabric
        icmp_inner = IcmpPacket(
            sip='2.2.2.3',
            dip='1.1.1.3',
            icmp_type=0,
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
        rcv_pkt = fabric_interface.send_and_receive_packet(
            pkt, tenant_vif, pkt)

        # Check if the packet was sent to vrouter (by vtest) on fabric
        # and received at vif5 (by vtest)
        self.assertEqual(1, fabric_interface.get_vif_ipackets())
        self.assertEqual(1, tenant_vif.get_vif_opackets())
