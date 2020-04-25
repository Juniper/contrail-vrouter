#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

class VmToFabricInterVn(unittest.TestCase):

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
        self.agent_vif = AgentVif(
            idx=2,
            flags=constants.VIF_FLAG_L3_ENABLED)

        # Add tenant vif
        self.tenant_vif = VirtualVif(
            name="tap03eb4be8-d8",
            ipv4_str="1.1.1.3",
            mac_str="00:00:5e:00:01:00",
            idx=3,
            vrf=2,
            mcast_vrf=2,
            nh_idx=24)

        # Add vif Nexthop
        self.vif_nh = EncapNextHop(
            encap_oif_id=self.tenant_vif.idx(),
            encap="02 03 eb 4b e8 d8 00 00 5e 00 01 00 08 00",
            nh_idx=24,
            nh_vrf=2,
            nh_flags=constants.NH_FLAG_POLICY_ENABLED)

        # Add tunnel NH
        self.tunnel_nh = TunnelNextHopV4(
            encap_oif_id=self.fabric_interface.idx(),
            encap="00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00",
            tun_sip="8.0.0.2",
            tun_dip="8.0.0.3",
            nh_idx=22,
            nh_flags=constants.NH_FLAG_TUNNEL_UDP_MPLS |
            constants.NH_FLAG_ETREE_ROOT)

        # Add Tunnel NH
        self.rl2_nh = ReceiveL2NextHop(
            nh_idx=3,
            nh_vrf=2,
            nh_flags=constants.NH_FLAG_ETREE_ROOT,
            encap_oif_id=self.tenant_vif.idx())

        # Add overlay L2 Route
        self.bridge_route = BridgeRoute(
            vrf=2,
            mac_str="00:00:5e:00:01:00",
            nh_idx=3,
            rtr_label_flags=constants.VR_BE_FLOOD_DHCP_FLAG)

        # Add overlay L3 Route
        self.inet_route = InetRoute(
            vrf=2,
            prefix="2.2.2.3",
            nh_idx=22,
            rtr_label_flags=constants.VR_RT_LABEL_VALID_FLAG |
            constants.VR_RT_ARP_PROXY_FLAG,
            rtr_label=23)

        # sync_all
        ObjectBase.sync_all()

        # Add forward and reverse flow and link them
        self.f_flow = InetFlow(
            sip='1.1.1.3',
            dip='2.2.2.3',
            sport=1418,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flow_nh_idx=24,
            src_nh_idx=24,
            flow_vrf=2,
            rflow_nh_idx=22)
        self.r_flow = InetFlow(
            sip='2.2.2.3',
            dip='1.1.1.3',
            sport=1418,
            dport=0,
            proto=constants.VR_IP_PROTO_ICMP,
            flags=constants.VR_RFLOW_VALID,
            flow_nh_idx=24,
            src_nh_idx=22,
            flow_vrf=2,
            rflow_nh_idx=22)
        self.f_flow.sync_and_link_flow(self.r_flow)
        self.assertGreater(self.f_flow.get_fr_index(), 0)

    def teardown_method(self, method):
        ObjectBase.tearDown()
