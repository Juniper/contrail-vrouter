#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *  # noqa

# anything with *test* will be assumed by pytest as a test


class TestNh32(unittest.TestCase):

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

    # tc to add, del nh with nhid > 65k
    def test1_nh32(self):

        # Add a Vif interface
        vif = VirtualVif(
            name="tap_1",
            ipv4_str="1.1.1.10",
            mac_str="de:ad:be:ef:00:02",
            idx=1,
            flags=None,
            nh_idx=494949,
            ipv6_str="571:3896:c427:3738:30c4:fd9f:720e:fefe")
        vif.sync()

        # Query the vif back
        vif_get = VirtualVif(
            name="tap_1",
            ipv4_str="1.1.1.10",
            mac_str="fe:ad:be:ef:00:02",
            idx=1,
            h_op=constants.SANDESH_OPER_GET)
        vif_get.sync()

        self.assertEqual(494949, vif_get.get_vif_nh_id())

        # Add NH
        encap_nh = EncapNextHop(
            encap_oif_id=vif.idx(),
            encap="de ad be ef 01 02 de ad be ef 00 01 08 00",
            nh_idx=490496,
            nh_family=constants.AF_BRIDGE)
        encap_nh.sync()

        # Get the same NH back
        nh_get = EncapNextHop(
            encap_oif_id=vif.idx(),
            encap=None,
            nh_idx=490496,
            nh_family=constants.AF_BRIDGE,
            h_op=constants.SANDESH_OPER_GET)
        nh_get.sync()

        self.assertEqual(490496, nh_get.get_nh_idx())
        self.assertEqual(constants.AF_BRIDGE, nh_get.get_nh_family())
        self.assertEqual(constants.NH_TYPE_ENCAP, nh_get.get_nh_type())

    # tc to add, del flow with nhid > 65k
    def test2_nh32(self):

        # Add vif - 10.1.1.1
        vif1 = VirtualVif(
            name="tap_1",
            ipv4_str="10.1.1.1",
            mac_str="de:ad:be:ef:00:02",
            idx=1,
            nh_idx=494949,
            flags=None)
        vif1.sync()

        # Add 2nd vif - 10.1.1.2
        vif2 = VirtualVif(
            name="tap_2",
            ipv4_str="10.1.1.2",
            mac_str="ed:da:eb:fe:00:03",
            nh_idx=474747,
            flags=None,
            idx=2)
        vif2.sync()

        # Add NH
        encap_nh = EncapNextHop(
            encap_oif_id=vif2.idx(),
            encap="de ad be ef 01 02 de ad be ef 00 01 08 00",
            nh_idx=474747,
            nh_family=constants.AF_BRIDGE)
        encap_nh.sync()

        # Add route which points to the NH
        rt = BridgeRoute(
            vrf=0,
            mac_str="de:ad:be:ef:02:02",
            nh_idx=474747)
        rt.sync()

        # Add flow
        flow = InetFlow(
            sip='1.1.1.1',
            dip='2.2.2.2',
            sport=31,
            dport=31,
            proto=17,
            action=2,
            src_nh_idx=494949,
            flow_nh_idx=594949)
        flow.sync(resp_required=True)
        flow.delete()
