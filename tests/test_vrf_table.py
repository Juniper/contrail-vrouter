#!/usr/bin/python
import os
import sys
import unittest
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
import vtest_common
from vrf import *
from flow import *
from route import *
from nexthop import *
from vif import *
import vtconst


# anything with *test* will be assumed by pytest as a test

class TestVrfTable(unittest.TestCase, vtest_common.VTestCommon):

    @classmethod
    def setup_class(cls):
        VTestObjectBase.setUpClass()

    @classmethod
    def teardown_class(cls):
        VTestObjectBase.tearDownClass()

    def setup_method(self, method):
        VTestObjectBase.setUp(method)

    def teardown_method(self, method):
        VTestObjectBase.tearDown()


    def test_vrf_table_new(self):
        # Add hbs-l vif
        vif = VirtualVif(
            idx=3,
            name="tap1589a2b3-22",
            ipv4_str="100.100.100.4",
            mac_str="00:00:5e:00:01:00",
            vrf=3,
            flags=vtconst.VIF_FLAG_POLICY_ENABLED | vtconst.VIF_FLAG_HBS_LEFT)
        vif.sync()

        # check if hbs-l vif got added
        self.assertIn("tap1589a2b3-22", vif.get('vifr_name'))

        # Add hbs-r vif
        vif = VirtualVif(
            idx=4,
            name="tap8b05a86b-36",
            ipv4_str="200.200.200.4",
            mac_str="00:00:5e:00:01:00",
            vrf=4,
            flags=vtconst.VIF_FLAG_POLICY_ENABLED | vtconst.VIF_FLAG_HBS_RIGHT)
        vif.sync()

        # check if hbs-r vif got added
        self.assertIn("tap8b05a86b-36", vif.get('vifr_name'))

        # Add tenant vif
        vif = VirtualVif(idx=5, name="tapc2234cd0-55", ipv4_str="1.0.0.3",
                         mac_str="00:00:5e:00:01:00", vrf=5,
                         flags=vtconst.VIF_FLAG_POLICY_ENABLED, nh_id=38)
        vif.sync()

        # check if tenant vif got added
        self.assertIn("tapc2234cd0-55", vif.get('vifr_name'))

        # Add hbs-l in vrf table
        vrf = Vrf(0, 5, vtconst.VRF_FLAG_HBS_L_VALID, vrf_hbfl_vif_idx=3)
        vrf.sync()

        # Add hbs-r in vrf table
        vrf = Vrf(0, 5, vtconst.VRF_FLAG_HBS_R_VALID, vrf_hbfr_vif_idx=4)
        vrf.sync()

        # Remove hbs-r in vrf table
        vrf = Vrf(0, 5, vtconst.VRF_FLAG_HBS_R_VALID, vrf_hbfr_vif_idx=-1)
        vrf.sync()

        # Remove hbs-l in vrf table
        vrf = Vrf(0, 5, vtconst.VRF_FLAG_HBS_L_VALID, vrf_hbfl_vif_idx=-1)
        vrf.sync()

        # Add hbs-l and hbs-r
        vrf = Vrf(
            0,
            5,
            vtconst.VRF_FLAG_HBS_L_VALID | vtconst.VRF_FLAG_HBS_R_VALID,
            vrf_hbfl_vif_idx=3,
            vrf_hbfr_vif_idx=4)
        vrf.delete()

        # Remove hbs-l and hbs-r in vrf table
        vrf = Vrf(
            0,
            5,
            vtconst.VRF_FLAG_HBS_R_VALID | vtconst.VRF_FLAG_HBS_R_VALID,
            vrf_hbfl_vif_idx=-1,
            vrf_hbfr_vif_idx=-1)
        vrf.sync()

        # Remove vrf entry in vrf table
        vrf = Vrf(0, 5)
        vrf.delete()
