#!/usr/bin/python

from topo_base.vm_to_vm_inter_vn import VmToVmInterVn
import os
import sys
import pytest
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestVmToVmInterVn(VmToVmInterVn):

    def test_vm_to_vm_inter_vn(self):

        # send ping request from vif3
        icmp = IcmpPacket(
            sip='1.1.1.4',
            dip='2.2.2.4',
            smac='02:88:67:0c:2e:11',
            dmac='00:00:5e:00:01:00',
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet
        rec_pkt = self.vif3.send_and_receive_packet(pkt, self.vif4)
        # check if we got ICMP packet
        self.assertTrue(ICMP in rec_pkt)
        self.assertEqual('1.1.1.4', rec_pkt[IP].src)
        self.assertEqual('2.2.2.4', rec_pkt[IP].dst)

        # send ping request from vif4
        icmp = IcmpPacket(
            sip='2.2.2.4',
            dip='1.1.1.4',
            smac='02:e7:03:ea:67:f1',
            dmac='00:00:5e:00:01:00',
            icmp_type=0,
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet
        rec_pkt = self.vif4.send_and_receive_packet(pkt, self.vif3)
        # check if we got ICMP packet
        self.assertTrue(ICMP in rec_pkt)
        self.assertEqual('2.2.2.4', rec_pkt[IP].src)
        self.assertEqual('1.1.1.4', rec_pkt[IP].dst)

        # Check if the packet was received at vif3 and vif4
        self.assertEqual(1, self.vif3.get_vif_opackets())
        self.assertEqual(1, self.vif3.get_vif_ipackets())

        self.assertEqual(1, self.vif4.get_vif_opackets())
        self.assertEqual(1, self.vif4.get_vif_ipackets())
