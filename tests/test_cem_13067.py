#!/usr/bin/python

from topo_base.fabric_to_vm_intra_vn import FabricToVmIntraVn
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestFabricToVmIntraVn(FabricToVmIntraVn):

    def test_fabric_to_vm_inter_vn(self):
        # Tunnel nexthop
        self.tun_nh = TunnelNextHopV4(
            encap_oif_id=self.fabric_interface.idx(),
            encap="00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00",
            tun_sip="1.1.1.5",
            tun_dip="1.1.1.3",
            nh_idx=24,
            nh_flags=constants.NH_FLAG_TUNNEL_UDP_MPLS |
            constants.NH_FLAG_ETREE_ROOT)

        # Add Bridge Route
        self.bridge_route = BridgeRoute(
            vrf=0,
            mac_str="02:e7:03:ea:67:f1",
            nh_idx=24,
            rtr_label=128,
            rtr_label_flags=3)

        # Add Nexthop
        self.nh = TranslateNextHop(
            nh_idx=84,
            nh_vrf=0,
            nh_family=constants.AF_BRIDGE)

        # Add Vxlan
        self.vxlan = Vxlan(
                vxlan_idx=0x32,
                vxlan_nhid=84)

        ObjectBase.sync_all()

        # send mplsudp packet from fabric
        icmp_inner = IcmpPacket(
            sip='1.1.1.5',
            dip='1.1.1.3',
            smac='02:c2:23:4c:d0:55',
            dmac='02:e7:03:ea:67:f1',
            icmp_type=constants.ECHO_REPLY,
            id=4145)
        pkt = icmp_inner.get_packet()
        self.assertIsNotNone(pkt)

        vxlan = VxlanPacket(
            vnid=0x32,
            sip='8.0.0.3',
            dip='8.0.0.2',
            smac='00:1b:21:bb:f9:46',
            dmac='00:1b:21:bb:f9:48',
            sport=53363,
            dport=4789,
            flags=0x08,
            inner_pkt=pkt)
        pkt = vxlan.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        self.fabric_interface.send_packet(pkt)

        # Get dropstats
        drop_stats = DropStats()
        self.assertEqual(1, drop_stats.get_vds_invalid_source())
