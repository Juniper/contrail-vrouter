#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

class FabricToVmInterVn(unittest.TestCase):

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
