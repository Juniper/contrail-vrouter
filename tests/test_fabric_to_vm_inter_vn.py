#!/usr/bin/python

from topo_base.fabric_to_vm_inter_vn import FabricToVmInterVn
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestFabricToVmInterVn(FabricToVmInterVn):

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
