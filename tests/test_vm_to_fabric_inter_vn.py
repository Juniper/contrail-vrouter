#!/usr/bin/python

from topo_base.vm_to_fabric_inter_vn import VmToFabricInterVn
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestVmToFabricInterVn(VmToFabricInterVn):

    def test_vm_to_fabric_inter_vn(self):
        icmp_inner = IcmpPacket(
            sip='1.1.1.3',
            dip='2.2.2.3',
            smac='02:03:eb:4b:e8:d8',
            dmac='00:00:5e:00:01:00',
            id=1418)
        pkt = icmp_inner.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # send packet
        self.tenant_vif.send_packet(pkt)

        # Check if the packet was sent from tenant vif to fabric
        self.assertEqual(1, self.fabric_interface.get_vif_opackets())
