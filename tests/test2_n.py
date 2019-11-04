#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')

from test_vtest_common import *
import vtconst
import pytest

# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test

class TestClass(vTestCommon, object):
    @classmethod
    def setup_method(cls, method):
        super(TestClass, cls).setUpClass(method)

    @classmethod
    def teardown_method(cls, method):
        super(TestClass, cls).tearDownClass(method)

    def test_1(self):
        uf = util_functions()
        vif = uf.create_vif(1, None, "tap_1", None, vt_ipv4('1.1.1.10'), vt_mac('de:ad:be:ef:00:02'), None)
        uf.send_sandesh_req(vif)

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

        uf.send_pkt(pkt, "tap_1")

        # get the dropstats
        drop_stats = dropstats()
        drop_stats_resp = uf.send_sandesh_req(drop_stats, uf.VT_RESPONSE_REQD)

        invalid_arp = uf.parse_xml_field(drop_stats_resp, "vds_invalid_arp")
        print "Got invalid arp count ", invalid_arp
        assert (invalid_arp.find("1") != -1), "Test 2 failed"
        return 0
