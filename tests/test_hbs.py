#!/usr/bin/python

from topo_base.fabric_to_vm_inter_vn import FabricToVmInterVn
from topo_base.fabric_to_vm_intra_vn import FabricToVmIntraVn
from topo_base.vm_to_fabric_inter_vn import VmToFabricInterVn
from topo_base.vm_to_fabric_intra_vn import VmToFabricIntraVn
from topo_base.vm_to_vm_inter_vn import VmToVmInterVn
from topo_base.vm_to_vm_intra_vn import VmToVmIntraVn
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa


class TestHbsFabricToVmInterVn(FabricToVmInterVn):

    def test_hbs_fabric_to_vm_inter_vn(self):

        # Add hbs-l vif
        hbs_l_vif = VirtualVif(
            name="tap1589a2b3-22",
            ipv4_str="100.100.100.4",
            mac_str="00:00:5e:00:01:00",
            idx=3,
            vrf=3,
            flags=constants.VIF_FLAG_HBS_LEFT)
        hbs_l_vif.sync()

        # Add hbs-r vif
        hbs_r_vif = VirtualVif(
            name="tap8b05a86b-36",
            ipv4_str="200.200.200.4",
            mac_str="00:00:5e:00:01:00",
            idx=4,
            vrf=4,
            flags=constants.VIF_FLAG_HBS_RIGHT)
        hbs_r_vif.sync()

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

        self.f_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_LEFT
        self.r_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_RIGHT
        self.f_flow.sync()
        self.r_flow.sync()

        # send mplsudp packet from fabric
        icmp_inner = IcmpPacket(
            sip='2.2.2.3',
            dip='1.1.1.3',
            icmp_type=constants.ECHO_REPLY,
            id=4145)
        pkt = icmp_inner.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)
        mpls = MplsoUdpPacket(
            label=42,
            sip='8.0.0.3',
            dip='8.0.0.2',
            smac='00:1b:21:bb:f9:46',
            dmac='00:1b:21:bb:f9:48',
            sport=53363,
            dport=6635,
            id=10,
            inner_pkt=pkt)
        pkt = mpls.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # Make sure the packet comes goes to hbs-r (tap8b05a86b-36)
        rcv_pkt = self.fabric_interface.send_and_receive_packet(
            pkt, hbs_r_vif)

        # TODO: Send the rcv_pkt to the next call instead of
        #       forming a new packet
        # Inject the packet from hbs-l to vrouter
        # Encode the flow id in the dst mac of the packet
        icmp = IcmpPacket(
            sip='1.0.0.5',
            dip='1.0.0.3',
            smac='00:00:5e:00:01:00',
            dmac='c0:d2:00:06:08:f0',
            icmp_type=0,
            id=4145)
        pkt = icmp.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # Send it to hbs-l
        rcv_pkt = hbs_l_vif.send_and_receive_packet(pkt, self.tenant_vif)

        # Check if the packet was sent to vrouter (by vtest) on fabric
        # and received at tenant_vif (by vtest)
        self.assertEqual(1, self.fabric_interface.get_vif_ipackets())
        self.assertEqual(1, self.tenant_vif.get_vif_opackets())

        # Check if the packet was sent to hbs-r (by vrouter)
        # and received at hbs-l (by vtest)
        self.assertEqual(1, hbs_r_vif.get_vif_opackets())
        self.assertEqual(1, hbs_l_vif.get_vif_ipackets())


class TestHbsFabricToVmIntraVn(FabricToVmIntraVn):

    def test_hbs_fabric_to_vm_intra_vn(self):

        # Add hbs-l vif
        hbs_l_vif = VirtualVif(
            name="tap1589a2b3-22",
            ipv4_str="100.100.100.4",
            mac_str="00:00:5e:00:01:00",
            idx=3,
            vrf=3,
            flags=constants.VIF_FLAG_HBS_LEFT)
        hbs_l_vif.sync()

        # Add hbs-r vif
        hbs_r_vif = VirtualVif(
            name="tap8b05a86b-36",
            ipv4_str="200.200.200.4",
            mac_str="00:00:5e:00:01:00",
            idx=4,
            vrf=4,
            flags=constants.VIF_FLAG_HBS_RIGHT)
        hbs_r_vif.sync()

        # Add Bridge Route
        bridge_route = BridgeRoute(
            vrf=5,
            mac_str="02:c2:23:4c:d0:55",
            nh_idx=44)
        bridge_route.sync()

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

        self.f_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_LEFT
        self.r_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_RIGHT
        self.f_flow.sync()
        self.r_flow.sync()

        # send mplsudp packet from fabric
        icmp_inner = IcmpPacket(
            sip='1.1.1.5',
            dip='1.1.1.3',
            smac='02:e7:03:ea:67:f1',
            dmac='02:c2:23:4c:d0:55',
            icmp_type=constants.ECHO_REPLY,
            id=4145)
        pkt = icmp_inner.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)
        mpls = MplsoUdpPacket(
            label=42,
            sip='8.0.0.3',
            dip='8.0.0.2',
            smac='00:1b:21:bb:f9:46',
            dmac='00:1b:21:bb:f9:48',
            sport=53363,
            dport=6635,
            id=10,
            inner_pkt=pkt)
        pkt = mpls.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # Make sure the packet comes goes to hbs-r (tap8b05a86b-36)
        hbsr_pkt = self.fabric_interface.send_and_receive_packet(
            pkt, hbs_r_vif)

        # Send it to hbs-l
        tenant_pkt = hbs_l_vif.send_and_receive_packet(
              hbsr_pkt, self.tenant_vif)

        self.assertIsNotNone(tenant_pkt)
        self.assertTrue(ICMP in tenant_pkt)
        self.assertEqual("1.1.1.5", tenant_pkt[IP].src)
        self.assertEqual("1.1.1.3", tenant_pkt[IP].dst)
        self.assertEqual("02:c2:23:4c:d0:55", tenant_pkt[Ether].dst)
        self.assertEqual("02:e7:03:ea:67:f1", tenant_pkt[Ether].src)

        # Check if the packet was sent to vrouter (by vtest) on fabric
        # and received at tenant_vif (by vtest)
        self.assertEqual(1, self.fabric_interface.get_vif_ipackets())
        self.assertEqual(1, self.tenant_vif.get_vif_opackets())

        # Check if the packet was sent to hbs-r (by vrouter)
        # and received at hbs-l (by vtest)
        self.assertEqual(1, hbs_r_vif.get_vif_opackets())
        self.assertEqual(1, hbs_l_vif.get_vif_ipackets())

    def test_hbs_cem_11144(self):

        # Add hbs-l vif
        hbs_l_vif = VirtualVif(
            name="tap1589a2b3-22",
            ipv4_str="100.100.100.4",
            mac_str="00:00:5e:00:01:00",
            idx=3,
            vrf=3,
            flags=constants.VIF_FLAG_HBS_LEFT)
        hbs_l_vif.sync()

        # Add hbs-r vif
        hbs_r_vif = VirtualVif(
            name="tap8b05a86b-36",
            ipv4_str="200.200.200.4",
            mac_str="00:00:5e:00:01:00",
            idx=4,
            vrf=4,
            flags=constants.VIF_FLAG_HBS_RIGHT)
        hbs_r_vif.sync()

        # Add Bridge Route
        bridge_route = BridgeRoute(
            vrf=5,
            mac_str="02:c2:23:4c:d0:55",
            nh_idx=44)
        bridge_route.sync()

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

        self.f_flow.delete()
        self.r_flow.delete()

        # send mplsudp packet from fabric
        # This creates a flow in hold state
        icmp_inner = IcmpPacket(
            sip='1.1.1.5',
            dip='1.1.1.3',
            smac='02:e7:03:ea:67:f1',
            dmac='02:c2:23:4c:d0:55',
            icmp_type=constants.ECHO_REPLY,
            id=4145)
        pkt = icmp_inner.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)
        mpls = MplsoUdpPacket(
            label=42,
            sip='8.0.0.3',
            dip='8.0.0.2',
            smac='00:1b:21:bb:f9:46',
            dmac='00:1b:21:bb:f9:48',
            sport=53363,
            dport=6635,
            id=10,
            inner_pkt=pkt)
        pkt = mpls.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # Send the packet from fabric
        rcv_pkt = self.fabric_interface.send_packet(
            pkt)

        # Flow is created but in Hold state
        # Set forwarding action for rflow now
        self.r_flow.fr_gen_id = self.r_flow.fr_gen_id + 1
        self.r_flow.fr_flags = constants.VR_FLOW_FLAG_ACTIVE
        self.r_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_RIGHT
        self.r_flow.sync(resp_required=True)

        # Wait for some time for the held packet to be flushed by vrouter
        time.sleep(2)

        # Check if the flushed packet was sent by vrouter on hbs-r
        self.assertEqual(1, hbs_r_vif.get_vif_opackets())


class TestHbsVmToFabricInterVn(VmToFabricInterVn):

    def test_hbs_vm_to_fabric_inter_vn(self):

        # Add hbs-l vif
        hbs_l_vif = VirtualVif(
            name="tap1589a2b3-22",
            ipv4_str="100.100.100.4",
            mac_str="00:00:5e:00:01:00",
            idx=4,
            vrf=3,
            flags=constants.VIF_FLAG_HBS_LEFT)
        hbs_l_vif.sync()

        # Add hbs-r vif
        hbs_r_vif = VirtualVif(
            name="tap8b05a86b-36",
            ipv4_str="200.200.200.4",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=4,
            flags=constants.VIF_FLAG_HBS_RIGHT)
        hbs_r_vif.sync()

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

        self.f_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_LEFT
        self.r_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_RIGHT
        self.f_flow.sync()
        self.r_flow.sync()

        icmp_pkt = IcmpPacket(
            sip='1.1.1.3',
            dip='2.2.2.3',
            smac='02:03:eb:4b:e8:d8',
            dmac='00:00:5e:00:01:00',
            id=1418)
        pkt = icmp_pkt.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # send packet
        hbfl_pkt = self.tenant_vif.send_and_receive_packet(pkt, hbs_l_vif)
        self.assertIsNotNone(hbfl_pkt)
        hbfl_pkt.show()

        # Send it to hbs-r and expect response on fabric
        fab_pkt = hbs_r_vif.send_and_receive_packet(
            hbfl_pkt, self.fabric_interface)
        self.assertIsNotNone(fab_pkt)
        fab_pkt.show()

        # Check if fabric got a MPLSoUDP packet
        self.assertTrue((UDP in fab_pkt) and (fab_pkt[UDP].dport == 6635))

        # Check if the packet was sent to vrouter (by vtest) on tenant_vif
        # and received at fabric (by vtest)
        self.assertEqual(1, self.tenant_vif.get_vif_ipackets())
        self.assertEqual(1, self.fabric_interface.get_vif_opackets())

        # Check if the packet was sent to hbs-l (by vrouter)
        # and received at hbs-r (by vtest)
        self.assertEqual(1, hbs_l_vif.get_vif_opackets())
        self.assertEqual(1, hbs_r_vif.get_vif_ipackets())


class TestHbsVmToFabricIntraVn(VmToFabricIntraVn):

    def test_hbs_vm_to_fabric_intra_vn(self):

        # Add hbs-l vif
        hbs_l_vif = VirtualVif(
            name="tap1589a2b3-22",
            ipv4_str="100.100.100.4",
            mac_str="00:00:5e:00:01:00",
            idx=3,
            vrf=3,
            flags=constants.VIF_FLAG_HBS_LEFT)
        hbs_l_vif.sync()

        # Add hbs-r vif
        hbs_r_vif = VirtualVif(
            name="tap8b05a86b-36",
            ipv4_str="200.200.200.4",
            mac_str="00:00:5e:00:01:00",
            idx=4,
            vrf=4,
            flags=constants.VIF_FLAG_HBS_RIGHT)
        hbs_r_vif.sync()

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

        self.f_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_LEFT
        self.r_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_RIGHT
        self.f_flow.sync()
        self.r_flow.sync()

        # send ping request from tenant_vif
        icmp = IcmpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            smac='02:c2:23:4c:d0:55',
            dmac='02:e7:03:ea:67:f1',
            id=4145)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet and receive on hbs-l
        hbsl_pkt = self.tenant_vif.send_and_receive_packet(pkt, hbs_l_vif)

        # Inject the packet from hbs-r to vrouter
        # Encode the flow id in the src mac of the packet
        icmp = IcmpPacket(
            sip='1.0.0.3',
            dip='1.0.0.5',
            smac='ca:f1:00:00:d9:d4',
            dmac='02:e7:03:ea:67:f1',
            id=4145)
        pkt = icmp.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # Send it to hbs-r and expect response on fabric vif
        fabric_pkt = hbs_r_vif.send_and_receive_packet(hbsl_pkt, self.fabric_vif)

        self.assertIsNotNone(fabric_pkt)
        self.assertTrue(UDP in fabric_pkt)
        self.assertEqual(6635, fabric_pkt[UDP].dport)
        self.assertEqual("8.0.0.2", fabric_pkt[IP].src)
        self.assertEqual("8.0.0.3", fabric_pkt[IP].dst)

        # Check if the packet was sent to vrouter (by vtest) on tenant_vif
        # and received at fabric (by test)
        self.assertEqual(1, self.tenant_vif.get_vif_ipackets())
        self.assertEqual(1, self.fabric_vif.get_vif_opackets())

        # Check if the packet was sent to hbs-l (by vrouter)
        # and received at hbs-r (by vtest)
        self.assertEqual(1, hbs_l_vif.get_vif_opackets())
        self.assertEqual(1, hbs_r_vif.get_vif_ipackets())


class TestHbsVmToVmInterVn(VmToVmInterVn):

    def test_hbs_vm_to_vm_inter_vn(self):

        # Add hbs-l vif
        hbs_l_vif = VirtualVif(
            name="tap3",
            ipv4_str="100.100.100.4",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=3,
            flags=constants.VIF_FLAG_HBS_LEFT)
        hbs_l_vif.sync()

        # Add hbs-r vif
        hbs_r_vif = VirtualVif(
            name="tap4",
            ipv4_str="200.200.200.4",
            mac_str="00:00:5e:00:01:00",
            idx=6,
            vrf=4,
            flags=constants.VIF_FLAG_HBS_RIGHT)
        hbs_r_vif.sync()

        # Add vif3 Nexthop (bridge)
        # pkt from hbs-r to vif 3 will need a lookup of dst-mac
        # in the bridge table
        # this is because dmac would have been encoded with flow id
        vif3_nhb = EncapNextHop(
            encap_oif_id=self.vif3.idx(),
            encap="02 88 67 0c 2e 11 00 00 5e 00 01 00 08 00",
            nh_idx=27,
            nh_family=constants.AF_BRIDGE,
            nh_vrf=3,
            nh_flags=constants.NH_FLAG_POLICY_ENABLED |
            constants.NH_FLAG_ETREE_ROOT)
        vif3_nhb.sync()

        # Add bridge Route
        bridge_route = BridgeRoute(
            vrf=3,
            mac_str="02:88:67:0c:2e:11",
            nh_idx=27)
        bridge_route.sync()

        # Add hbs-l and hbs-r in the vrf table
        vrf = Vrf(
            vrf_rid=0,
            vrf_idx=3,
            vrf_flags=constants.VRF_FLAG_VALID |
            constants.VRF_FLAG_HBS_L_VALID |
            constants.VRF_FLAG_HBS_R_VALID,
            vrf_hbfl_vif_idx=5,
            vrf_hbfr_vif_idx=6)
        vrf.sync()

        # Add hbs-l and hbs-r in the vrf table
        vrf = Vrf(
            vrf_rid=0,
            vrf_idx=4,
            vrf_flags=constants.VRF_FLAG_VALID |
            constants.VRF_FLAG_HBS_L_VALID |
            constants.VRF_FLAG_HBS_R_VALID,
            vrf_hbfl_vif_idx=5,
            vrf_hbfr_vif_idx=6)
        vrf.sync()

        self.f_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_LEFT
        self.r_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_RIGHT
        self.f_flow.sync()
        self.r_flow.sync()

        # send ping request from vif3 and receive in hbs-l
        icmp = IcmpPacket(
            sip='1.1.1.4',
            dip='2.2.2.4',
            smac='02:88:67:0c:2e:11',
            dmac='00:00:5e:00:01:00',
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet
        hbsl_pkt = self.vif3.send_and_receive_packet(pkt, hbs_l_vif)

        # send hbsl packet to hbs-r
        vif4_pkt = hbs_r_vif.send_and_receive_packet(hbsl_pkt, self.vif4)
        # check if we got ICMP packet
        self.assertTrue(ICMP in vif4_pkt)
        self.assertEqual('1.1.1.4', vif4_pkt[IP].src)
        self.assertEqual('2.2.2.4', vif4_pkt[IP].dst)

        # send ping response from tenant_vif4 and receive in hbs-r
        icmp = IcmpPacket(
            sip='2.2.2.4',
            dip='1.1.1.4',
            smac='02:e7:03:ea:67:f1',
            dmac='00:00:5e:00:01:00',
            icmp_type=constants.ECHO_REPLY,
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # send packet
        hbsr_pkt = self.vif4.send_and_receive_packet(pkt, hbs_r_vif)
        hbsr_pkt.show()

        # TODO: Use hbsr_pkt instead of this
        #
        # send ping response from hbs-r and receive in tenant_vif3
        icmp = IcmpPacket(
            sip='2.2.2.4',
            dip='1.1.1.4',
            smac='00:00:5e:00:01:00',
            dmac='c0:d1:00:04:05:8c',
            icmp_type=constants.ECHO_REPLY,
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        # send packet
        vif3_pkt = hbs_l_vif.send_and_receive_packet(pkt, self.vif3)
        # check if we got ICMP packet
        self.assertTrue(ICMP in vif4_pkt)
        self.assertEqual('2.2.2.4', vif3_pkt[IP].src)
        self.assertEqual('1.1.1.4', vif3_pkt[IP].dst)

        # Check if the packet was sent on tenant_vif3 and received at hbs-l
        self.assertEqual(1, self.vif3.get_vif_ipackets())
        self.assertEqual(1, hbs_l_vif.get_vif_opackets())

        # Check if the packet was sent to hbs-r and received from tenant_vif4
        self.assertEqual(1, hbs_r_vif.get_vif_opackets())
        self.assertEqual(1, self.vif4.get_vif_ipackets())

        # Check if the packet was sent on tenant_vif4 and received at hbs-r
        self.assertEqual(1, self.vif4.get_vif_opackets())
        self.assertEqual(1, hbs_r_vif.get_vif_ipackets())

        # Check if the packet was sent to hbs-l and received from tenant_vif3
        self.assertEqual(1, self.vif3.get_vif_opackets())
        self.assertEqual(1, hbs_l_vif.get_vif_ipackets())


class TestHbsVmToVmIntraVn(VmToVmIntraVn):

    def test_hbs_left_vm_to_right_vm_intra_vm(self):

        # Add hbs-l vif
        hbs_l_vif = VirtualVif(
            name="tap1589a2b3-22",
            ipv4_str="100.100.100.4",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=3,
            flags=constants.VIF_FLAG_HBS_LEFT)
        hbs_l_vif.sync()

        # Add hbs-r vif
        hbs_r_vif = VirtualVif(
            name="tap8b05a86b-36",
            ipv4_str="200.200.200.4",
            mac_str="00:00:5e:00:01:00",
            idx=6,
            vrf=4,
            flags=constants.VIF_FLAG_HBS_RIGHT)
        hbs_r_vif.sync()

        # Add hbs-l and hbs-r in the vrf table
        vrf = Vrf(
            vrf_rid=0,
            vrf_idx=2,
            vrf_flags=constants.VRF_FLAG_VALID |
            constants.VRF_FLAG_HBS_L_VALID |
            constants.VRF_FLAG_HBS_R_VALID,
            vrf_hbfl_vif_idx=5,
            vrf_hbfr_vif_idx=6)
        vrf.sync()

        self.f_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_LEFT
        self.r_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_RIGHT
        self.f_flow.sync()
        self.r_flow.sync()

        # send ping request from tenant_vif3
        icmp = IcmpPacket(
            sip='1.1.1.4',
            dip='1.1.1.5',
            smac='02:88:67:0c:2e:11',
            dmac='02:e7:03:ea:67:f1',
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet and receive on hbs-l
        hbsl_pkt = self.vif3.send_and_receive_packet(pkt, hbs_l_vif)

        # send the packet on hbs-r and receive in vif4
        vif4_pkt = hbs_r_vif.send_and_receive_packet(hbsl_pkt, self.vif4)

        self.assertIsNotNone(vif4_pkt)
        self.assertTrue(ICMP in vif4_pkt)
        self.assertEqual("1.1.1.4", vif4_pkt[IP].src)
        self.assertEqual("1.1.1.5", vif4_pkt[IP].dst)

        # Check if the packet was sent on tenant_vif3 and received at
        # tenant_vif4
        self.assertEqual(1, self.vif3.get_vif_ipackets())
        self.assertEqual(1, self.vif4.get_vif_opackets())

        # Check if the packet was sent to hbs-l and received from hbs-r
        self.assertEqual(1, hbs_l_vif.get_vif_opackets())
        self.assertEqual(1, hbs_r_vif.get_vif_ipackets())

    def test_hbs_right_vm_to_left_vm_intra_vn(self):

        # Add hbs-l vif
        hbs_l_vif = VirtualVif(
            name="tap1589a2b3-22",
            ipv4_str="100.100.100.4",
            mac_str="00:00:5e:00:01:00",
            idx=5,
            vrf=3,
            flags=constants.VIF_FLAG_HBS_LEFT)
        hbs_l_vif.sync()

        # Add hbs-r vif
        hbs_r_vif = VirtualVif(
            name="tap8b05a86b-36",
            ipv4_str="200.200.200.4",
            mac_str="00:00:5e:00:01:00",
            idx=6,
            vrf=4,
            flags=constants.VIF_FLAG_HBS_RIGHT)
        hbs_r_vif.sync()

        # Add hbs-l and hbs-r in the vrf table
        vrf = Vrf(
            vrf_rid=0,
            vrf_idx=2,
            vrf_flags=constants.VRF_FLAG_VALID |
            constants.VRF_FLAG_HBS_L_VALID |
            constants.VRF_FLAG_HBS_R_VALID,
            vrf_hbfl_vif_idx=5,
            vrf_hbfr_vif_idx=6)
        vrf.sync()

        self.f_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_LEFT
        self.r_flow.fr_flags1 = constants.VR_FLOW_FLAG1_HBS_RIGHT
        self.f_flow.sync()
        self.r_flow.sync()

        # send ping request from vif4
        icmp = IcmpPacket(
            sip='1.1.1.5',
            dip='1.1.1.4',
            smac='02:e7:03:ea:67:f1',
            dmac='02:88:67:0c:2e:11',
            icmp_type=constants.ECHO_REPLY,
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet and receive on hbs-r
        hbsr_pkt = self.vif4.send_and_receive_packet(pkt, hbs_r_vif)

        # send packet in hbsl and receive on vif3
        vif3_pkt = hbs_l_vif.send_and_receive_packet(hbsr_pkt, self.vif3)

        self.assertIsNotNone(vif3_pkt)
        self.assertTrue(ICMP in vif3_pkt)
        self.assertEqual("1.1.1.5", vif3_pkt[IP].src)
        self.assertEqual("1.1.1.4", vif3_pkt[IP].dst)

        # Check if the packet was sent on vif4 and received at
        # vif3
        self.assertEqual(1, self.vif4.get_vif_ipackets())
        self.assertEqual(1, self.vif3.get_vif_opackets())

        # Check if the packet was sent to hbs-r and received from hbs-l
        self.assertEqual(1, hbs_r_vif.get_vif_opackets())
        self.assertEqual(1, hbs_l_vif.get_vif_ipackets())
