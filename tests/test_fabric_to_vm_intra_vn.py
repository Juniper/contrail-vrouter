#!/usr/bin/python

from imports import *
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')


# anything with *test* will be assumed by pytest as a test

class TestFabricToVmIntraVn(unittest.TestCase):

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

    def test_fabric_to_vm_intra_vn(self):

        # Add fabric interface
        fabric_interface = FabricVif(
            name="eth1",
            mac_str="00:1b:21:bb:f9:48",
            idx=0)

        # Add vhost0 vif
        vhost0_vif = VhostVif(
            ipv4_str="8.0.0.2",
            mac_str="00:1b:21:bb:f9:48",
            idx=1)

        # Add agent vif
        agent_vif = AgentVif(idx=2)

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
            nh_vrf=5)

        # Add underlay Receive NH
        underlay_rnh = ReceiveNextHop(
            encap_oif_id=1,
            nh_idx=10,
            nh_vrf=1)

        # Add underlay Route
        underlay_route = InetRoute(
            vrf=0,
            prefix="8.0.0.2",
            nh_idx=10)

        # Add Encap L2 Nexthop for overlay
        l2_nh = EncapNextHop(
            encap_oif_id=5,
            encap="02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00",
            nh_idx=44,
            nh_family=constants.AF_BRIDGE,
            nh_vrf=5)

        # Add MPLS entry for overlay
        mpls_entry = Mpls(
            mr_label=42,
            mr_nhid=44)

        # Add tunnel NH (for src validation)
        tunnel_nh = TunnelNextHopV4(
            encap_oif_id=0,
            encap="00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00",
            tun_sip="8.0.0.2",
            tun_dip="8.0.0.3",
            nh_idx=21)
        ObjectBase.sync_all()

        # Add forward and reverse flow and link them
        f_flow = InetFlow(sip='1.1.1.3', dip='1.1.1.5', sport=4145, dport=0,
                          proto=constants.VR_IP_PROTO_ICMP, flow_nh_idx=38,
                          src_nh_idx=38, flow_vrf=5, rflow_nh_idx=21)
        r_flow = InetFlow(sip='1.1.1.5', dip='1.1.1.3', sport=4145, dport=0,
                          proto=constants.VR_IP_PROTO_ICMP, flow_nh_idx=38,
                          src_nh_idx=21, flow_vrf=5, rflow_nh_idx=21)
        f_flow.sync_and_link_flow(r_flow)
        self.assertGreater(f_flow.get_fr_index(), 0)

        # send mplsudp packet from fabric
        icmp_inner = IcmpPacket(
            sip='2.2.2.3',
            dip='1.1.1.3',
            smac='02:c2:23:4c:d0:55',
            dmac='02:e7:03:ea:67:f1',
            icmp_type=0)
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

        # send packet
        rcv_pkt = fabric_interface.send_and_receive_packet(
            pkt, tenant_vif, pkt)

        # Check if the packet was received at tenant vif
        self.assertEqual(1, tenant_vif.get_vif_opackets())
