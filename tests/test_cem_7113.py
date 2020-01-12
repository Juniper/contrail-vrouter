#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *

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
        fabric_vif = FabricVif(name='eth1', mac_str='00:1b:21:bb:f9:46', vrf=0, 
                    mcast_vrf=65535, flags=constants.VIF_FLAG_VHOST_PHYS)

        # Add vhost0 vif
        vhost_vif = VhostVif(idx=1, ipv4_str='8.0.0.3', 
                                mac_str='00:1b:21:bb:f9:46',nh_id=5,
                                flags=(constants.VIF_FLAG_L3_ENABLED |\
                                    constants.VIF_FLAG_DHCP_ENABLED))

        # Add agent vif
        agent_vif = AgentVif(idx=2, flags=constants.VIF_FLAG_L3_ENABLED)

        # Add tenant vif
        tenant_vif = VirtualVif(idx=3, name='tape703ea67-f1', ipv4_str='1.1.1.5',
                            mac_str='00:00:5e:00:01:00', nh_id=21, vrf=2, mcast_vrf=2,
                            flags=(constants.VIF_FLAG_POLICY_ENABLED |\
                                    constants.VIF_FLAG_DHCP_ENABLED))

        # Add tenant vif nexthop
        tenant_vif_nh = EncapNextHop(encap_oif_id=tenant_vif.idx(),
                            encap="02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00",
                            nh_id=21,
                            nh_vrf=2,
                            nh_flags=(constants.NH_FLAG_VALID |\
                                    constants.NH_FLAG_POLICY_ENABLED),
                            encap_family=constants.VR_ETH_PROTO_ARP) 

        # Add vhost0 vif nexthop
        vhost_vif_nh = EncapNextHop(encap_oif_id=vhost_vif.idx(),
                            encap='00 1b 21 bb f9 46 00 1b 21 bb f9 46 08 00',
                            nh_id=5,
                            nh_vrf=0,
                            nh_flags=(constants.NH_FLAG_VALID |\
                                    constants.NH_FLAG_POLICY_ENABLED),
                            encap_family=constants.VR_ETH_PROTO_ARP)

        # Add fabric vif netxhop
        fabric_vif_nh = EncapNextHop(encap_oif_id=fabric_vif.idx(),
                            encap="90 e2 ba 84 48 88 00 1b 21 bb f9 46 08 00",
                            nh_id=16, 
                            nh_vrf=0,
                            nh_flags=constants.NH_FLAG_VALID,
                            encap_family=constants.VR_ETH_PROTO_ARP)

        # Add receive nexthop
        receive_nh = ReceiveNextHop(encap_oif_id=vhost_vif.idx(), 
                                nh_vrf=1, nh_id=10,
                                nh_flags=(constants.NH_FLAG_VALID |\
                                        constants.NH_FLAG_RELAXED_POLICY))

        # Add fabric Route 
        fabric_route = InetRoute(vrf=0, prefix="8.0.0.3", nh_id=receive_nh.idx(),
                            rtr_label_flags=constants.VR_RT_ARP_TRAP_FLAG)

        # Add tenant Route
        tenant_route = InetRoute(vrf=2, prefix="1.1.1.5", nh_id=tenant_vif_nh.idx(),
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
                        proto=constants.VR_IP_PROTO_UDP, flow_nh_id=5,
                        src_nh_idx=16, flow_vrf=0, flow_dvrf=2,
                        rflow_sip="1.1.1.5", rflow_dip="169.254.169.7",
                        rflow_nh_id=21, rflow_sport=33596, flags=fflags)

        rflags = constants.VR_FLOW_FLAG_ACTIVE |\
                    constants.VR_RFLOW_VALID |\
                    constants.VR_FLOW_FLAG_VRFT |\
                    constants.VR_FLOW_FLAG_SNAT |\
                    constants.VR_FLOW_FLAG_DNAT |\
                    constants.VR_FLOW_FLAG_SPAT
        #Add reverse Flow
        rflow = NatFlow(sip="1.1.1.5", dip="169.254.169.7", sport=33596, dport=53,
                        proto=constants.VR_IP_PROTO_UDP, flow_nh_id=21,
                        src_nh_idx=21, flow_vrf=2, flow_dvrf=0,
                        rflow_sip="8.0.0.1", rflow_dip="8.0.0.3",
                        rflow_nh_id=5, rflow_sport=53, flags=rflags)

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
