#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

'''
vif --list
----------
Vrouter Interface Table

vif0/0      PCI: Mock
            Type:Physical HWaddr:00:1b:21:bb:f9:46 IPaddr:0.0.0.0
            Vrf:0 Mcast Vrf:65535 Flags:L3L2Vp QOS:0 Ref:10
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:1  bytes:70 errors:0
            Drops:0
            TX port   packets:1 errors:0 syscalls:1

vif0/1      PMD: vhost0 Mock NH: 5
            Type:Host HWaddr:00:1b:21:bb:f9:46 IPaddr:10.1.1.1
            Vrf:0 Mcast Vrf:65535 Flags:L3D QOS:0 Ref:9
            RX port   packets:1 errors:0 syscalls:1
            RX queue  packets:1 errors:0
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0 0
            RX packets:1  bytes:42 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

vif0/2      Socket: unix Mock
            Type:Agent HWaddr:00:00:5e:00:01:00 IPaddr:0.0.0.0
            Vrf:65535 Mcast Vrf:65535 Flags:L3 QOS:0 Ref:7
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

vif0/3      PMD: tape703ea67-f1 NH: 21
            Type:Virtual HWaddr:00:00:5e:00:01:00 IPaddr:1.1.1.5
            Vrf:2 Mcast Vrf:2 Flags:PL3L2D QOS:0 Ref:8
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

nh --list
---------
Id:0        Type:Drop           Fmly: AF_INET  Rid:0  Ref_cnt:2805       Vrf:0
            Flags:Valid,

Id:5        Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:1          Vrf:0
            Flags:Valid,
            EncapFmly:0806 Oif:1 Len:14
            Encap Data: 00 1b 21 bb f9 46 00 1b 21 bb f9 46 08 00

Id:10       Type:Receive        Fmly: AF_INET  Rid:0  Ref_cnt:2          Vrf:1
            Flags:Valid,
            Oif:1

Id:16       Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:1          Vrf:0
            Flags:Valid,
            EncapFmly:0806 Oif:0 Len:14
            Encap Data: 90 e2 ba 84 48 88 00 1b 21 bb f9 46 08 00

Id:21       Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:3          Vrf:2
            Flags:Valid,
            EncapFmly:0806 Oif:3 Len:14
            Encap Data: 02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00

Id:50       Type:Tunnel         Fmly: AF_INET  Rid:0  Ref_cnt:2          Vrf:0
            Flags:Valid, MPLSoGRE,
            Oif:0 Len:14 Data:08 e2 ba 84 48 88 00 1b 21 bb f9 46 08 00
            Sip:10.1.1.1 Dip:20.1.1.1

Id:51       Type:Composite      Fmly: AF_INET  Rid:0  Ref_cnt:2          Vrf:0
            Flags:Valid, Ecmp,
            Sub NH(label): 21(0) 50(10)


rt --dump 0
-----------
1.1.1.5/32             32            P          -             51        -

'''


class Test_CEM_13716(unittest.TestCase):

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

    def test_cem_13716(self):
        # Add fabric vif
        fabric_vif = FabricVif(
            name='eth0',
            mac_str='00:1b:21:bb:f9:46')

        # Add vhost0 vif
        vhost_vif = VhostVif(
            idx=1,
            ipv4_str='10.1.1.1',
            mac_str='00:1b:21:bb:f9:46',
            nh_idx=5)

        # Add agent vif
        agent_vif = AgentVif(idx=2, flags=constants.VIF_FLAG_L3_ENABLED)

        # Add tenant vif
        tenant_vif = VirtualVif(
            idx=3,
            name='tape703ea67-f1',
            ipv4_str='1.1.1.5',
            mac_str='00:00:5e:00:01:00',
            nh_idx=21,
            vrf=2,
            mcast_vrf=2)

        # Add tenant vif nexthop
        tenant_vif_nh = EncapNextHop(
            encap_oif_id=tenant_vif.idx(),
            encap="02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00",
            nh_idx=21,
            nh_vrf=2,
            encap_family=constants.VR_ETH_PROTO_ARP)

        # Add vhost0 vif nexthop
        vhost_vif_nh = EncapNextHop(
            encap_oif_id=vhost_vif.idx(),
            encap='00 1b 21 bb f9 46 00 1b 21 bb f9 46 08 00',
            nh_idx=5,
            encap_family=constants.VR_ETH_PROTO_ARP)

        # Add fabric vif netxhop
        fabric_vif_nh = EncapNextHop(
            encap_oif_id=fabric_vif.idx(),
            encap="90 e2 ba 84 48 88 00 1b 21 bb f9 46 08 00",
            nh_idx=16,
            encap_family=constants.VR_ETH_PROTO_ARP)

        # Add receive nexthop
        receive_nh = ReceiveNextHop(
            encap_oif_id=vhost_vif.idx(),
            nh_vrf=1,
            nh_idx=10)

        # Add a tunnel nexthop
        tunnel_nh = TunnelNextHopV4(
            encap_oif_id=fabric_vif.idx(),
            encap="08 e2 ba 84 48 88 00 1b 21 bb f9 46 08 00",
            tun_sip="10.1.1.1", tun_dip="20.1.1.1", nh_idx=50,
            nh_flags=(constants.NH_FLAG_VALID | constants.NH_FLAG_TUNNEL_GRE))

        # Add composite ecmp nexthop
        comp_flags = (constants.NH_FLAG_VALID |
                      constants.NH_FLAG_COMPOSITE_ECMP)
        comp_ecmp_nh = CompositeNextHop(nh_idx=51, nh_family=constants.AF_INET,
                                        nh_vrf=0, nh_flags=comp_flags)
        comp_ecmp_nh.add_nexthop(0, tenant_vif_nh.idx())
        comp_ecmp_nh.add_nexthop(10, tunnel_nh.idx())

        # Add fabric Route
        fabric_route = InetRoute(
            vrf=0,
            prefix="10.1.1.1",
            nh_idx=receive_nh.idx(),
            rtr_label_flags=constants.VR_RT_ARP_TRAP_FLAG)

        # Add tenant Route
        tenant_route = InetRoute(
            vrf=2,
            prefix="1.1.1.5",
            nh_idx=tenant_vif_nh.idx(),
            rtr_label_flags=constants.VR_RT_ARP_PROXY_FLAG)

        # Add IP forwarding local ECMP route for the tenant
        tenant_route_vrf0 = InetRoute(
            vrf=0,
            prefix="1.1.1.5",
            nh_idx=comp_ecmp_nh.idx(),
            rtr_label_flags=constants.VR_RT_ARP_PROXY_FLAG)

        # Sync all objects created above
        ObjectBase.sync_all()

        # create a ping pkt
        icmp = IcmpPacket(
            sip='10.1.1.1',
            dip='1.1.1.5',
            smac='00:00:5e:00:01:00',
            dmac='00:00:5e:00:01:00',
            id=1136)
        pkt = icmp.get_packet()
        pkt.show()

        # send packet through vhost0 and receive on fabric
        fab_pkt = vhost_vif.send_and_receive_packet(pkt, fabric_vif)
        fab_pkt.show()

        # Verify the pkt dst mac and dst IP
        self.assertEqual('08:e2:ba:84:48:88', fab_pkt[Ether].dst)
        self.assertEqual('20.1.1.1', fab_pkt[IP].dst)
