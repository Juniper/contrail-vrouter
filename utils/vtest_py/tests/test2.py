#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
from vtest_lib import *


def test2(vrouter_test_fixture):
    vt_path = os.environ['VTEST_PATH']
    sock_dir = os.environ['VROUTER_SOCKET_PATH']

    vt = vtest("test2", vt_path, sock_dir)

    # Add a Vif interface
    vif = vr_interface_req()
    vif.h_op = sandeshenum.SANDESH_OPER_ADD
    vif.vifr_type = sandeshenum.SANDESH_VIF_TYPE_VIRTUAL
    vif.vifr_idx = 1
    vif.vifr_name = "1"
    vif.vifr_transport = sandeshenum.SANDESH_VIF_TRANSPORT_PMD
    vif.vifr_vrf = 0
    vif.vifr_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x02]
    vif.vifr_mtu = 1514
    vif.vifr_ip = 16843018

    vif_list = []
    vif_list.append(vif)
    vt.send_sandesh_req(vif_list)

    # create an invalid unicast ARP pkt which should get dropped in vrouter
    ether = Ether()
    arp = ARP()
    ether.src = "de:ad:be:ef:00:02"
    ether.dst = "de:ad:be:ef:00:00"
    arp.op = 1
    arp.hwtype = 0x1
    arp.hwlen = 7
    pkt = ether/arp
    pkt.show()

    vt.send_pkt(pkt, "1")

    # get the dropstats
    drop_stats = vr_drop_stats_req()
    drop_stats.h_op = sandeshenum.SANDESH_OPER_GET

    cmd_list = []
    cmd_list.append(drop_stats)
    drop_stats_resp = vt.send_sandesh_req(cmd_list, vt.VT_RESPONSE_REQD)

    invalid_arp = vt.parse_xml_field(drop_stats_resp[0], "vds_invalid_arp")
    print "Got invalid arp count ", invalid_arp
    assert (invalid_arp.find("1") != -1), "Test 2 failed"
    return 0


def main():
    test2()


if __name__ == "__main__":
    main()
