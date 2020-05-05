#!/usr/bin/python

import os
import sys
import pytest
import subprocess
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestTcpReset(unittest.TestCase):

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
            name="tap1",
            ipv4_str="1.1.1.4",
            mac_str="00:00:5e:00:01:00",
            vrf=3,
            mcast_vrf=3,
            nh_idx=23)

        # Add tenant vif4
        self.vif4 = VirtualVif(
            idx=4,
            name="tap2",
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
            dport=500,
            proto=constants.VR_IP_PROTO_TCP,
            flow_nh_idx=23,
            src_nh_idx=23,
            flow_vrf=3,
            rflow_nh_idx=28)

        self.r_flow = InetFlow(
            sip='2.2.2.4',
            dip='1.1.1.4',
            sport=1136,
            dport=500,
            proto=constants.VR_IP_PROTO_TCP,
            flow_nh_idx=28,
            flags=constants.VR_RFLOW_VALID,
            src_nh_idx=28,
            flow_vrf=4,
            rflow_nh_idx=23)
        self.f_flow.sync_and_link_flow(self.r_flow)
        self.assertGreater(self.f_flow.get_fr_index(), 0)

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def test_tcp_reset_0(self):
        check_flow_delete_cmd = ("cd ../../../../../vrouter/tests ;"
                                 "./run_test.py -c 'flow --get '")

        ether_1 = Ether(src='02:88:67:0c:2e:11', dst='00:00:5e:00:01:00',
                        type=0x800)
        ip_1 = IP(src='1.1.1.4', dst='2.2.2.4', version=4, ihl=5,
                  id=1, ttl=64, proto='tcp')

        ether_2 = Ether(src='02:e7:03:ea:67:f1', dst='00:00:5e:00:01:00',
                        type=0x800)
        ip_2 = IP(src='2.2.2.4', dst='1.1.1.4', version=4, ihl=5,
                  id=2, ttl=64, proto='tcp')

        tcp = TCP(flags='S', seq=1, sport=1136, dport=500)
        syn_pkt = ether_1 / ip_1 / tcp
        syn_pkt.show()
        self.vif3.send_packet(syn_pkt)

        tcp = TCP(flags='SA', sport=1136, dport=500, seq=1,
                  ack=syn_pkt.seq + 1)
        syn_ack_pkt = ether_2 / ip_2 / tcp
        syn_ack_pkt.show()
        self.vif4.send_packet(syn_ack_pkt)

        tcp = TCP(flags='A', sport=1136, dport=500, seq=syn_ack_pkt.ack,
                  ack=syn_ack_pkt.seq + 1)
        ack_pkt = ether_1 / ip_1 / tcp
        ack_pkt.show()
        self.vif3.send_packet(ack_pkt)

        # Case when vr_close_flow_on_tcp_rst is zero (Default)
        # Flow will not be closed on RST packet
        tcp = TCP(flags='R', sport=1136, dport=500, seq=ack_pkt.ack)
        rst_pkt = ether_2 / ip_2 / tcp
        rst_pkt.show()
        self.vif4.send_packet(rst_pkt)

        check_flow_delete_cmd += str(self.f_flow.get_fr_index())
        flow_stats = subprocess.check_output(check_flow_delete_cmd, shell=True)

        self.assertEqual(0, ("EVICTED" in flow_stats))
