#!/usr/bin/python

from imports import *
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')


# anything with *test* will be assumed by pytest as a test

class TestHbsVmToFabricInterVn(unittest.TestCase):

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

    def test_hbs_vm_to_fabric_inter_vn(self):

        # Add fabric interface
        fabric_interface = FabricVif(
            name="eth1",
            mac_str="00:1b:21:bb:f9:48",
            idx=0,
            flags=constants.VIF_FLAG_VHOST_PHYS)
        fabric_interface.sync()

        # Add vhost0 vif
        vhost0_vif = VhostVif(
            ipv4_str="8.0.0.2",
            mac_str="00:1b:21:bb:f9:48",
            idx=1,
            flags=constants.VIF_FLAG_L3_ENABLED |
            constants.VIF_FLAG_DHCP_ENABLED)
        vhost0_vif.sync()

        # Add agent vif
        agent_vif = AgentVif(
            idx=2,
            flags=constants.VIF_FLAG_L3_ENABLED)
        agent_vif.sync()

        # Add tenant vif
        tenant_vif = VirtualVif(
            name="tap03eb4be8-d8",
            ipv4_str="1.1.1.3",
            mac_str="00:00:5e:00:01:00",
            idx=3,
            nh_idx=24,
            vrf=2,
            mcast_vrf=2,
            flags=constants.VIF_FLAG_POLICY_ENABLED |
            constants.VIF_FLAG_DHCP_ENABLED)
        tenant_vif.sync()

        # Add hbs-l vif
        hbs_l_vif = VirtualVif(
            name="tap1589a2b3-22",
            ipv4_str="100.100.100.4",
            mac_str="00:00:5e:00:01:00",
            idx=4,
            vrf=3,
            flags=constants.VIF_FLAG_POLICY_ENABLED |
            constants.VIF_FLAG_HBS_LEFT)
        hbs_l_vif.sync()

        # Add hbs-r vif
        hbs_r_vif = VirtualVif(
            name="tap8b05a86b-36",
            ipv4_str="200.200.200.4",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=4,
            flags=constants.VIF_FLAG_POLICY_ENABLED |
            constants.VIF_FLAG_HBS_RIGHT)
        hbs_r_vif.sync()

        # Add vif Nexthop
        vif_nh = EncapNextHop(
            encap_oif_id=3,
            encap="02 03 eb 4b e8 d8 00 00 5e 00 01 00 08 00",
            nh_idx=24,
            nh_vrf=2,
            nh_flags=constants.NH_FLAG_VALID |
            constants.NH_FLAG_POLICY_ENABLED)
        vif_nh.sync()

        # Add tunnel NH
        tunnel_nh1 = TunnelNextHopV4(
            encap_oif_id=0,
            encap="00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00",
            tun_sip="8.0.0.2",
            tun_dip="8.0.0.3",
            nh_idx=22,
            nh_flags=constants.NH_FLAG_VALID |
            constants.NH_FLAG_TUNNEL_UDP_MPLS |
            constants.NH_FLAG_ETREE_ROOT)
        tunnel_nh1.sync()

        # Add tunnel NH
        tunnel_nh2 = ReceiveL2NextHop(
            nh_idx=3,
            nh_vrf=2,
            encap_oif_id=3,
            nh_flags=constants.NH_FLAG_VALID |
            constants.NH_FLAG_ETREE_ROOT)
        tunnel_nh2.sync()

        # Add overlay L2 Route
        bridge_route = BridgeRoute(
            vrf=2,
            mac_str="00:00:5e:00:01:00",
            nh_idx=3,
            rtr_label_flags=constants.VR_BE_FLOOD_DHCP_FLAG)
        bridge_route.sync()

        # Add overlay L3 Route
        inet_route = InetRoute(
            vrf=2,
            prefix="2.2.2.3",
            nh_idx=22,
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG |
            constants.VR_RT_ARP_PROXY_FLAG,
            rtr_label=23)
        inet_route.sync()

        # Add hbs-l and hbs-r in vrf table
        vrf = Vrf(
            vrf_rid=0,
            vrf_idx=2,
            vrf_flags=constants.VRF_FLAG_VALID |
            constants.VRF_FLAG_HBS_L_VALID |
            constants.VRF_FLAG_HBS_R_VALID,
            vrf_hbfl_vif_idx=4,
            vrf_hbfr_vif_idx=5)
        vrf.sync()

        # Add forward and reverse flow and link them
        f_flow = InetFlow(
            sip='1.1.1.3',
            dip='2.2.2.3',
            sport=1418,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flow_nh_idx=24,
            ecmp_nh_index=-1,
            qos_id=-1,
            src_nh_idx=24,
            flow_vrf=2,
            ridx=-1,
            rflow_nh_idx=22,
            flags1=constants.VR_FLOW_FLAG1_HBS_LEFT)
        r_flow = InetFlow(
            sip='2.2.2.3',
            dip='1.1.1.3',
            sport=1418,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flags=constants.VR_FLOW_FLAG_ACTIVE |
            constants.VR_RFLOW_VALID,
            flow_nh_idx=24,
            ecmp_nh_index=-1,
            qos_id=-1,
            src_nh_idx=22,
            flow_vrf=2,
            rflow_nh_idx=22,
            flags1=constants.VR_FLOW_FLAG1_HBS_RIGHT)
        f_flow.sync_and_link_flow(r_flow)
        self.assertGreater(f_flow.get_fr_index(), 0)

        icmp = IcmpPacket(
            sip='1.1.1.3',
            dip='2.2.2.3',
            smac='02:03:eb:4b:e8:d8',
            dmac='00:00:5e:00:01:00',
            icmp_type=8,
            id=1418)
        pkt = icmp.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # send packet
        rcv_pkt = tenant_vif.send_and_receive_packet(pkt, hbs_l_vif, pkt)

        # Inject the packet from hbs-r to vrouter
        # Encode the flow id in the src mac of the packet
        icmp = IcmpPacket(
            sip='1.1.1.3',
            dip='2.2.2.3',
            smac='ca:f1:00:03:b1:40',
            dmac='00:00:5e:00:01:00',
            icmp_type=8,
            id=1418)
        pkt = icmp.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # Send it to hbs-r and expect response on fabric
        rcv_pkt = hbs_r_vif.send_and_receive_packet(pkt, fabric_interface, pkt)

        # Check if the packet was sent to vrouter (by vtest) on tenant_vif
        # and received at fabric (by vtest)
        self.assertEqual(1, tenant_vif.get_vif_ipackets())
        self.assertEqual(1, fabric_interface.get_vif_opackets())

        # Check if the packet was sent to hbs-l (by vrouter)
        # and received at hbs-r (by vtest)
        self.assertEqual(1, hbs_l_vif.get_vif_opackets())
        self.assertEqual(1, hbs_r_vif.get_vif_ipackets())
