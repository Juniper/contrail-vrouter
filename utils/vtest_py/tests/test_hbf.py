#!/usr/bin/python

import os
import sys
import ipaddress
import socket
sys.path.append(os.getcwd())
import vtconst
from vtest_lib import *

def test_hbf(vrouter_test_fixture):

    vt = vtest("test_hbf")

    # Add fabric interface
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_PHYSICAL
    vif.vifr_idx = 1
    vif.vifr_name = "1"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 0
    vif.vifr_mac = vt_mac("00:1b:21:bb:f9:48")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("8.0.0.2")

    vt.send_sandesh_req(vif)

   # Add hbf-l vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 3
    vif.vifr_name = "tap1589a2b3-22"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_flags = vtconst.VIF_FLAG_POLICY_ENABLED
    vif.vifr_vrf = 3
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("100.100.100.4")

    vt.send_sandesh_req(vif)

    # Add hbf-r vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 4
    vif.vifr_name = "tap8b05a86b-36"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 4
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("200.200.200.4")

    vt.send_sandesh_req(vif)

    # Add tenant vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 5
    vif.vifr_name = "tapc2234cd0-55"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 5
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("1.1.1.3")

    vt.send_sandesh_req(vif)

    # Add tunnel NH
    nh = vr_nexthop_req()
    nh.h_op = vtconst.SANDESH_OPER_ADD
    nh.nhr_type = vtconst.NH_TUNNEL
    nh.nhr_id = 21
    nh.nhr_encap_oif_id = 1
    nh.nhr_encap = vt_encap("00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00")
    nh.nhr_tun_sip = vt_ipv4("8.0.0.2")
    nh.nhr_tun_dip = vt_ipv4("8.0.0.3")
    nh.nhr_vrf = 0
    nh.nhr_family = socket.AF_INET
    nh.nhr_flags = vtconst.NH_FLAG_VALID |\
                   vtconst.NH_FLAG_TUNNEL_UDP_MPLS |\
                   vtconst.NH_FLAG_ETREE_ROOT
    vt.send_sandesh_req(nh)

    #Add bridge Route
    route = vr_route_req()
    route.h_op = vtconst.SANDESH_OPER_ADD
    route.rtr_family = vtconst.AF_BRIDGE
    route.rtr_nh_id = 21
    route.rtr_mac = vt_mac("02:e7:03:ea:67:f1")
    route.rtr_label = 27
    route.rtr_vrf_id = 5
    route.rtr_label_flags = vtconst.VR_RT_LABEL_VALID_FLAG |\
                            vtconst.VR_RT_ARP_PROXY_FLAG |\
                            vtconst.VR_BE_FLOOD_DHCP_FLAG
    
    vt.send_sandesh_req(route)

    eth = Ether(dst='02:e7:03:ea:67:f1', src='02:c2:23:4c:d0:55', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='icmp', src='1.1.1.3', dst='1.1.1.5')
    icmp = ICMP(type=8, code=0)
    pkt = eth/ip/icmp
    pkt.show()

    vt.send_pkt(pkt, "tapc2234cd0-55")

def main():
    test_hbf()


if __name__ == "__main__":
    main()
