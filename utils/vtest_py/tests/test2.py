#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from vtest_lib import *
import vtconst


def test2(vrouter_test_fixture):

    vt = vtest("test2")

    # Add a Vif interface
    vif = VIF(1, "tap_1", vt_ipv4("1.1.1.10"), vt_mac("de:ad:be:ef:00:02"))
    vt.send_sandesh_req(vif)

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

    vt.send_pkt(pkt, "tap_1")

    # get the dropstats
    drop_stats = DROPSTATS()
    drop_stats_resp = vt.send_sandesh_req(drop_stats, vt.VT_RESPONSE_REQD)

    invalid_arp = vt.parse_xml_field(drop_stats_resp, "vds_invalid_arp")
    print "Got invalid arp count ", invalid_arp
    assert (invalid_arp.find("1") != -1), "Test 2 failed"
    return 0
