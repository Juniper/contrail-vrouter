#!/usr/bin/python

from imports import *
import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')

# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test

#
# Test case:
# Do the following RT operations
# Addr = 10.60.7.0 plen = 25 vrf = 4 operation = ADD/CHANGE \
# nh_idx = 38 label = 410760
# Addr = 10.60.0.0 plen = 23 vrf = 4 operation = ADD/CHANGE \
# nh_idx = 38 label = 410760
# Addr = 10.60.7.128 plen = 25 vrf = 4 operation = ADD/CHANGE \
# nh_idx = 38 label = 410760
# Addr = 10.60.0.0 plen = 20 vrf = 4 operation = ADD/CHANGE \
# nh_idx = 2 label = 609700
# Addr = 10.60.0.0 plen = 20 vrf = 4 operation = DELETE nh_idx = 2
# After the above operations, rt get of 10.60.7.3/32 should \
# return nh = 38 and label = 410760.
# Similarly rt get of 10.60.7.144/32 should return nh = 38 \
# and label = 410760.
#


class TestCem11421(unittest.TestCase):

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

    def test_cem_11421(self):

        # Add the vif
        vif = VirtualVif(
            name="tap_1",
            ipv4_str="192.168.1.3",
            mac_str="de:ad:be:ef:00:02",
            idx=1)

        # Add Nexthop
        encap_nh = EncapNextHop(
            encap_oif_id=1,
            encap="de ad be ef 00 02 de ad be ef 00 01 08 00",
            nh_idx=38,
            nh_family=constants.AF_INET)

        # Add the vif
        vif = VirtualVif(
            name="tap2",
            ipv4_str="192.168.1.4",
            mac_str="de:ad:be:ef:00:04",
            idx=2)

        # Add Nexthop
        encap_nh = EncapNextHop(
            encap_oif_id=2,
            encap="de ad be ef 00 04 de ad be ef 00 01 08 00",
            nh_idx=2,
            nh_family=constants.AF_INET)

        # Add Inet Route
        inet_rt1 = InetRoute(
            vrf=4,
            prefix="10.60.7.0",
            nh_idx=38,
            prefix_len=25)

        # Add Inet Route
        inet_rt2 = InetRoute(
            vrf=4,
            prefix="10.60.0.0",
            nh_idx=38,
            prefix_len=23)

        # Add Inet Route
        inet_rt3 = InetRoute(
            vrf=4,
            prefix="10.60.7.128",
            nh_idx=38,
            prefix_len=25)

        # Add Inet Route
        inet_rt4 = InetRoute(
            vrf=4,
            prefix="10.60.0.0",
            nh_idx=2,
            prefix_len=20)

        # Add Inet Route
        inet_rt5 = InetRoute(
            vrf=4,
            prefix="10.60.0.0",
            nh_idx=2,
            prefix_len=20)

        # Query the routes back
        inet_rt6 = InetRoute(
            vrf=4,
            prefix="10.60.7.3",
            nh_idx=0,
            prefix_len=32)

        inet_rt7 = InetRoute(
            vrf=4,
            prefix="10.60.7.144",
            nh_idx=0,
            prefix_len=32)
        ObjectBase.sync_all()

        self.assertEqual(0, inet_rt7.get_rtr_nh_idx())
        self.assertEqual(0, inet_rt6.get_rtr_nh_idx())
