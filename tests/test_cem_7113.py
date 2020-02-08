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

Flags: P=Policy, X=Cross Connect, S=Service Chain, Mr=Receive Mirror
       Mt=Transmit Mirror, Tc=Transmit Checksum Offload, L3=Layer 3, L2=Layer 2
       D=DHCP, Vp=Vhost Physical, Pr=Promiscuous, Vnt=Native Vlan Tagged
       Mnp=No MAC Proxy, Dpdk=DPDK PMD Interface,
       Rfl=Receive Filtering Offload, Mon=Interface is Monitored
       Uuf=Unknown Unicast Flood, Vof=VLAN insert/strip offload,
       Df=Drop New Flows, L=MAC Learning Enabled
       Proxy=MAC Requests Proxied Always, Er=Etree Root,
       Mn=Mirror without Vlan Tag, Ig=Igmp Trap Enabled

vif0/0      PCI: Mock
            Type:Physical HWaddr:00:1b:21:bb:f9:46 IPaddr:0.0.0.0
            Vrf:0 Mcast Vrf:65535 Flags:L3L2Vp QOS:0 Ref:6
            RX port   packets:1 errors:0 syscalls:1
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:1  bytes:54 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

vif0/1      PMD: vhost0 Mock
            Type:Host HWaddr:00:1b:21:bb:f9:46 IPaddr:8.0.0.3
            Vrf:0 Mcast Vrf:65535 Flags:L3D QOS:0 Ref:7
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

vif0/2      Socket: unix Mock
            Type:Agent HWaddr:00:00:5e:00:01:00 IPaddr:0.0.0.0
            Vrf:65535 Mcast Vrf:65535 Flags:L3 QOS:0 Ref:5
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:0  bytes:0 errors:0
            Drops:0

vif0/3      PMD: tape703ea67-f1
            Type:Virtual HWaddr:00:00:5e:00:01:00 IPaddr:1.1.1.5
            Vrf:2 Mcast Vrf:2 Flags:PL3L2D QOS:0 Ref:6
            RX queue errors to lcore 0 0 0 0 0 0 0 0 0 0 0
            RX packets:0  bytes:0 errors:0
            TX packets:1  bytes:54 errors:0
            Drops:0
            TX port   packets:0 errors:1

nh --list
---------
Id:0        Type:Drop           Fmly: AF_INET  Rid:0  Ref_cnt:2041       Vrf:0
            Flags:Valid,

Id:5        Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:1          Vrf:0
            Flags:Valid, Policy,
            EncapFmly:0806 Oif:1 Len:14
            Encap Data: 00 1b 21 bb f9 46 00 1b 21 bb f9 46 08 00

Id:10       Type:Receive        Fmly: AF_INET  Rid:0  Ref_cnt:2          Vrf:1
            Flags:Valid, Policy(R),
            Oif:1

Id:16       Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:1          Vrf:0
            Flags:Valid,
            EncapFmly:0806 Oif:0 Len:14
            Encap Data: 90 e2 ba 84 48 88 00 1b 21 bb f9 46 08 00

Id:21       Type:Encap          Fmly: AF_INET  Rid:0  Ref_cnt:2          Vrf:2
            Flags:Valid, Policy,
            EncapFmly:0806 Oif:3 Len:14
            Encap Data: 02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00



flow -l
-------
Flow table(size 80609280, entries 629760)

Entries: Created 0 Added 2 Deleted 0 Changed 1Processed 0
Used Overflow entries 0
(Created Flows/CPU: 0 0 0 0 0 0 0 0 0 0 0)(oflows 0)

Action:F=Forward, D=Drop N=NAT(S=SNAT, D=DNAT, Ps=SPAT, Pd=DPAT,
L=Link Local Port)
Other:K(nh)=Key_Nexthop, S(nh)=RPF_Nexthop
Flags:E=Evicted, Ec=Evict Candidate, N=New Flow, M=Modified Dm=Delete Marked
TCP(r=reverse):S=SYN, F=FIN, R=RST, C=HalfClose, E=Established, D=Dead

Index                Source:Port/Destination:Port                      Proto(V)
-------------------------------------------------------------------------------
259944<=>323068       1.1.1.5:33596                                   17 (2->0)
                      169.254.169.7:53
(Gen: 1, K(nh):21, Action:N(SPsD), Flags:, QOS:-1, S(nh):21,  Stats:0/0,
 SPort 57139, TTL 0, Sinfo 0.0.0.0)

323068<=>259944       8.0.0.1:53                                     17 (0->2)
                      8.0.0.3:60185
(Gen: 1, K(nh):5, Action:N(SDPdL), Flags:, QOS:-1, S(nh):16,  Stats:1/40,
 SPort 52761, TTL 0, Sinfo 0.0.0.0)

rt --dump 0
-----------
8.0.0.3/32             32            T          -             10        -
8.0.0.30/32             0                       -              0        -


rt --dump 2
-----------
1.1.1.5/32             32            P          -             21        -
1.1.1.50/32             0                       -              0        -
'''


class Test_CEM_7113(unittest.TestCase):

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

    def test_cem_7113(self):
        # Add fabric vif
        fabric_vif = FabricVif(
            name='eth1',
            mac_str='00:1b:21:bb:f9:46',
            vrf=0,
            mcast_vrf=65535,
            flags=constants.VIF_FLAG_VHOST_PHYS)

        # Add vhost0 vif
        vhost_vif = VhostVif(idx=1, ipv4_str='8.0.0.3',
                             mac_str='00:1b:21:bb:f9:46', nh_idx=5,
                             flags=(constants.VIF_FLAG_L3_ENABLED |
                                    constants.VIF_FLAG_DHCP_ENABLED))

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
            mcast_vrf=2,
            flags=(constants.VIF_FLAG_POLICY_ENABLED |
                   constants.VIF_FLAG_DHCP_ENABLED))

        # Add tenant vif nexthop
        tenant_vif_nh = EncapNextHop(
            encap_oif_id=tenant_vif.idx(),
            encap="02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00",
            nh_idx=21,
            nh_vrf=2,
            nh_flags=(constants.NH_FLAG_VALID |
                      constants.NH_FLAG_POLICY_ENABLED),
            encap_family=constants.VR_ETH_PROTO_ARP)

        # Add vhost0 vif nexthop
        vhost_vif_nh = EncapNextHop(
            encap_oif_id=vhost_vif.idx(),
            encap='00 1b 21 bb f9 46 00 1b 21 bb f9 46 08 00',
            nh_idx=5,
            nh_vrf=0,
            nh_flags=(constants.NH_FLAG_VALID |
                      constants.NH_FLAG_POLICY_ENABLED),
            encap_family=constants.VR_ETH_PROTO_ARP)

        # Add fabric vif netxhop
        fabric_vif_nh = EncapNextHop(
            encap_oif_id=fabric_vif.idx(),
            encap="90 e2 ba 84 48 88 00 1b 21 bb f9 46 08 00",
            nh_idx=16,
            nh_vrf=0,
            nh_flags=constants.NH_FLAG_VALID,
            encap_family=constants.VR_ETH_PROTO_ARP)

        # Add receive nexthop
        receive_nh = ReceiveNextHop(
            encap_oif_id=vhost_vif.idx(),
            nh_vrf=1,
            nh_idx=10,
            nh_flags=(constants.NH_FLAG_VALID |
                      constants.NH_FLAG_RELAXED_POLICY))

        # Add fabric Route
        fabric_route = InetRoute(
            vrf=0,
            prefix="8.0.0.3",
            nh_idx=receive_nh.idx(),
            rtr_label_flags=constants.VR_RT_ARP_TRAP_FLAG)

        # Add tenant Route
        tenant_route = InetRoute(
            vrf=2,
            prefix="1.1.1.5",
            nh_idx=tenant_vif_nh.idx(),
            rtr_label_flags=constants.VR_RT_ARP_PROXY_FLAG)

        # Sync all objects created above
        ObjectBase.sync_all()

        # Add forward Flow
        fflags = constants.VR_FLOW_FLAG_ACTIVE |\
            constants.VR_FLOW_FLAG_VRFT |\
            constants.VR_FLOW_FLAG_SNAT |\
            constants.VR_FLOW_FLAG_DNAT |\
            constants.VR_FLOW_FLAG_DPAT |\
            constants.VR_FLOW_FLAG_LINK_LOCAL

        fflow = NatFlow(sip="8.0.0.1", dip="8.0.0.3", sport=53, dport=60185,
                        proto=constants.VR_IP_PROTO_UDP, flow_nh_idx=5,
                        src_nh_idx=16, flow_vrf=0, flow_dvrf=2,
                        rflow_sip="1.1.1.5", rflow_dip="169.254.169.7",
                        rflow_nh_idx=21, rflow_sport=33596, flags=fflags)

        rflags = constants.VR_FLOW_FLAG_ACTIVE |\
            constants.VR_RFLOW_VALID |\
            constants.VR_FLOW_FLAG_VRFT |\
            constants.VR_FLOW_FLAG_SNAT |\
            constants.VR_FLOW_FLAG_DNAT |\
            constants.VR_FLOW_FLAG_SPAT
        # Add reverse Flow
        rflow = NatFlow(
            sip="1.1.1.5",
            dip="169.254.169.7",
            sport=33596,
            dport=53,
            proto=constants.VR_IP_PROTO_UDP,
            flow_nh_idx=21,
            src_nh_idx=21,
            flow_vrf=2,
            flow_dvrf=0,
            rflow_sip="8.0.0.1",
            rflow_dip="8.0.0.3",
            rflow_nh_idx=5,
            rflow_sport=53,
            flags=rflags)

        fflow.sync_and_link_flow(rflow)

        # create dns packet
        dns = DnsPacket(sip="8.0.0.1", dip="8.0.0.3",
                        smac="90:e2:ba:84:48:88", dmac="00:1b:21:bb:f9:46",
                        sport=53, dport=60185)
        pkt = dns.get_packet()
        pkt.show()

        # send packet
        fabric_vif.send_packet(pkt)

        # Check if the packet was sent to tenant vif
        self.assertEqual(1, tenant_vif.get_vif_opackets())
