#!/usr/bin/python

from imports import *
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')


# anything with *test* will be assumed by pytest as a test

class TestHbsVmiToFabric(unittest.TestCase):

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

    def test_hbs_vmi_to_fabric(self):

        # Add fabric interface
        vif = FabricVif(
            name="eth0",
            mac_str="00:1b:21:bb:f9:48",
            ipv4_str="8.0.0.2")
        vif.sync()

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
            ipv4_str="1.0.0.3",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=5,
            nh_idx=38,
            flags=constants.VIF_FLAG_POLICY_ENABLED)
        tenant_vif.sync()

        # Add vif Nexthop
        vif_nh = EncapNextHop(
            encap_oif_id=5,
            encap="02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00",
            nh_idx=38,
            nh_vrf=5,
            nh_flags=constants.NH_FLAG_VALID |
            constants.NH_FLAG_POLICY_ENABLED)
        vif_nh.sync()

        # Add tunnel NH
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

        # Add bridge Route
        bridge_route = BridgeRoute(
            vrf=5,
            mac_str="02:e7:03:ea:67:f1",
            nh_idx=21,
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG |
            constants.VR_RT_ARP_PROXY_FLAG |
            constants.VR_BE_FLOOD_DHCP_FLAG,
            rtr_label=27)
        bridge_route.sync()

        # Add forward and reverse flow and link them
        f_flow = InetFlow(
            sip='1.0.0.3',
            dip='1.0.0.5',
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
            sip='1.0.0.5',
            dip='1.0.0.3',
            sport=4145,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flags=constants.VR_FLOW_FLAG_ACTIVE | constants.VR_RFLOW_VALID,
            ecmp_nh_index=-1,
            qos_id=-1,
            flow_nh_idx=38,
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

        # send ping request from tenant_vif
        icmp = IcmpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            smac='02:c2:23:4c:d0:55',
            dmac='02:e7:03:ea:67:f1',
            icmp_type=8,
            id=4145)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet and receive on hbs-l
        rcv_pkt = tenant_vif.send_and_receive_packet(pkt, hbs_l_vif, pkt)

        # Inject the packet from hbs-r to vrouter
        # Encode the flow id in the src mac of the packet
        icmp = IcmpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            smac='ca:f1:00:00:d9:d4',
            dmac='02:e7:03:ea:67:f1',
            icmp_type=8,
            id=4145)
        pkt = icmp.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # Send it to hbs-r and expect response on fabric vif
        rcv_pkt = hbs_r_vif.send_and_receive_packet(pkt, vif, pkt)

        # Check if the packet was sent to vrouter (by vtest) on tenant_vif
        # and received at fabric (by test)
        self.assertEqual(1, tenant_vif.get_vif_ipackets())
        self.assertEqual(1, vif.get_vif_opackets())

        # Check if the packet was sent to hbs-l (by vrouter)
        # and received at hbs-r (by vtest)
        self.assertEqual(1, hbs_l_vif.get_vif_opackets())
        self.assertEqual(1, hbs_r_vif.get_vif_ipackets())
