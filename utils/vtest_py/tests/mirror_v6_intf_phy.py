#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
from vtest_lib import *


# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test
def test_mirror_v6_sandesh_conf(vrouter_test_fixture):

    vt = vtest("test_mirror_v6_sandesh_conf")

    vif = vr_interface_req()
    vif.h_op = sandeshenum.SANDESH_OPER_ADD
    vif.vifr_type = sandeshenum.SANDESH_VIF_TYPE_PHYSICAL
    vif.vifr_idx = 1
    vif.vifr_name = "1"
    vif.vifr_transport = sandeshenum.SANDESH_VIF_TRANSPORT_PMD
    vif.vifr_vrf = 0
    vif.vifr_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x02]
    vif.vifr_mtu = 2514
    vif.vifr_flags = 0
    # add the vif
    vt.send_sandesh_req(vif)

    vif = vr_interface_req()
    vif.h_op = sandeshenum.SANDESH_OPER_ADD
    vif.vifr_type = sandeshenum.SANDESH_VIF_TYPE_PHYSICAL
    vif.vifr_idx = 2
    vif.vifr_name = "2"
    vif.vifr_transport = sandeshenum.SANDESH_VIF_TRANSPORT_PMD
    vif.vifr_vrf = 0
    vif.vifr_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]
    vif.vifr_mtu = 2514
    vif.vifr_flags = 1
    # add the vif
    vt.send_sandesh_req(vif)

    vif = vr_interface_req()
    vif.h_op = sandeshenum.SANDESH_OPER_ADD
    vif.vifr_type = sandeshenum.SANDESH_VIF_TYPE_VIRTUAL
    vif.vifr_idx = 3
    vif.vifr_name = "3"
    vif.vifr_transport = sandeshenum.SANDESH_VIF_TRANSPORT_PMD
    vif.vifr_vrf = 2
    vif.vifr_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]
    vif.vifr_mtu = 2514
    vif.vifr_flags = 1
    vif.vifr_nh_id = 21
    # add the vif
    vt.send_sandesh_req(vif)

    nh = vr_nexthop_req()
    nh.h_op = sandeshenum.SANDESH_OPER_ADD
    nh.nhr_type = sandeshenum.SANDESH_NH_TYPE_ENCAP
    nh.nhr_id = 21
    nh.nhr_encap_oif_id = 3
    nh.nhr_encap = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x02, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x08, 0x00]
    nh.nhr_vrf = 2
    nh.nhr_flags = 3
    nh.nhr_family = 2
    #Add Nexthop
    vt.send_sandesh_req(nh)

    nh = vr_nexthop_req()
    nh.h_op = sandeshenum.SANDESH_OPER_ADD
    nh.nhr_type = sandeshenum.SANDESH_NH_TYPE_TUNNEL
    nh.nhr_id = 14
    nh.nhr_encap_oif_id = 2
    nh.nhr_encap = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x02, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x08, 0x00]
    nh.nhr_tun_sip = 33685761
    nh.nhr_tun_dip = 16843266
    nh.nhr_vrf = 0
    nh.nhr_flags = 129
    #Add Nexthop
    vt.send_sandesh_req(nh)

    mirr = vr_mirror_req()
    mirr.h_op = sandeshenum.SANDESH_OPER_ADD
    mirr.mirr_index = 1
    mirr.mirr_nhid = 14
    mirr.mirr_flags = 0
    mirr.mirr_vni = 50
    #Add Mirror
    vt.send_sandesh_req(mirr)

    mpls = vr_mpls_req()
    mpls.h_op = sandeshenum.SANDESH_OPER_ADD
    mpls.mr_label = 48
    mpls.mr_nhid = 21
    #Add MPLS label
    vt.send_sandesh_req(mpls)


    nh = vr_nexthop_req()
    nh.h_op = sandeshenum.SANDESH_OPER_ADD
    nh.nhr_type = sandeshenum.SANDESH_NH_TYPE_RCV
    nh.nhr_id = 15
    nh.nhr_encap_oif_id = 1
    nh.nhr_vrf = 0
    nh.nhr_flags = 257
    nh.nhr_family = 2
    #Add Nexthop
    vt.send_sandesh_req(nh)

    route = vr_route_req()
    route.h_op = sandeshenum.SANDESH_OPER_ADD
    route.rtr_family = 2
    route.rtr_nh_id = 15
    route.rtr_prefix = [0x02, 0x02, 0x01, 0x01]
    route.rtr_prefix_len = 32
    route.rtr_vrf_id = 0
    #Add Route
    vt.send_sandesh_req(route)

    flow = vr_flow_req()
    flow.fr_op = sandeshenum.SANDESH_FLOW_OPER_SET
    flow.fr_flow_sip_l = 72057594037927936 #00:00:00:00:00:00:00:01
    flow.fr_flow_sip_u = 17221973885176569344 #00:DE:00:AD:00:BE:00:EF
    flow.fr_flow_dip_l = 144115188075855872 #00:00:00:00:00:00:00:02
    flow.fr_flow_dip_u = 17221973885176569344 #00:DE:00:AD:00:BE:00:EF
    flow.fr_family = 10
    flow.fr_index = -1
    flow.fr_flags = 8193
    flow.fr_extflags = 2
    flow.fr_flow_proto = 17
    flow.fr_flow_sport = 108
    flow.fr_flow_nh_id = 21
    flow.fr_action = 2
    flow.fr_flow_dport = 1
    flow.fr_mir_id = 1
    flow.fr_pcap_meta_data = [0xFF, 0xDE, 0xAD, 0xDE, 0xAD, 0xFF]
    #Add Flow
    vt.send_sandesh_req(flow)

    eth = Ether(dst='de:ad:be:ef:00:02', src='de:ad:be:ef:00:01', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='udp', src='1.1.2.2', dst='2.2.1.1')
    udp = UDP(sport=257, dport=6635)
    ipv6 =IPv6(version=6, nh=17, hlim=64, src='de:ad:be:ef::1', dst='de:ad:be:ef::2')
    udp2 = UDP(sport=27648, dport=256)
    load_contrib('mpls')
    pkt=eth/ip/udp/MPLS(label=48, ttl=64)/ipv6/udp2
    pkt.show()

    print "Expected mirror packet with VXLAN"

    eth = Ether(dst='de:ad:be:ef:00:02', src='de:ad:be:ef:00:01', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='udp', src='1.1.2.2', dst='2.2.1.1')
    udp = UDP(sport=4789, dport=4789, chksum=0x0000)
    vxlan = VXLAN(flags=0x08, reserved1=0x00, vni=0x32)
    eth2 = Ether(dst='de:ad:be:ef:00:02', src='de:ad:be:ef:00:01', type=0x86dd)
    ipv6 =IPv6(version=6, nh=17, hlim=64, src='de:ad:be:ef::1', dst='de:ad:be:ef::2')
    udp2 = UDP(sport=27648, dport=256)
    exp_pkt=eth/ip/udp/vxlan/eth2/ipv6/udp2
    exp_pkt.show()
    vt.send_recv_pkt(pkt, "1", exp_pkt, "2")

    # query the vif and see if it really got added
    vif = vr_interface_req()
    vif.h_op = 1
    vif.vifr_idx = 2

    vif_resp_file = vt.send_sandesh_req(vif, vt.VT_RESPONSE_REQD)

    # parse the fields and validate the response
    vif_name = vt.parse_xml_field(vif_resp_file, "vifr_name")
    print "Got vif name ", vif_name
    assert (vif_name.find("2") != -1), "Failed to get vif name"
    vif_opackets = vt.parse_xml_field(vif_resp_file, "vifr_opackets")
    print "Received mirror packets ", vif_opackets
    # Expecting one received packet and mirror packet.
    # Mirror packet would be received on physical interface "2"
    assert (vif_opackets.find("1") != -1), "Failed to receive Mirror packet"
    print "Test 1 passed"
    return 0


def main():
    test_mirror_v6_sandesh_conf()


if __name__ == "__main__":
    main()
