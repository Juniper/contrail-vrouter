#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from imports import *


# anything with *test* will be assumed by pytest as a test

class TestVrfTable(unittest.TestCase):

    @classmethod
    def setup_class(cls):
        ObjectBase.setUpClass()

    @classmethod
    def teardown_class(cls):
        ObjectBase.tearDownClass()

    def setup_method(self, method):
        ObjectBase.setUp(method)

    def teardown_method(self, method):
        ObjectBase.tearDown()

    def test_vrf_table(self):
        # Add hbs-l vif
        vif1 = VirtualVif(
            idx=3,
            name="tap1589a2b3-22",
            ipv4_str="100.100.100.4",
            mac_str="00:00:5e:00:01:00",
            vrf=3,
            flags=constants.VIF_FLAG_POLICY_ENABLED |
                    constants.VIF_FLAG_HBS_LEFT)
        vif1.sync()

        # Add hbs-r vif
        vif2 = VirtualVif(
            idx=4,
            name="tap8b05a86b-36",
            ipv4_str="200.200.200.4",
            mac_str="00:00:5e:00:01:00",
            vrf=4,
            flags=constants.VIF_FLAG_POLICY_ENABLED |
                    constants.VIF_FLAG_HBS_RIGHT)
        vif2.sync()

        # Add tenant vif
        vif3 = VirtualVif(idx=5, name="tapc2234cd0-55", ipv4_str="1.0.0.3",
                          mac_str="00:00:5e:00:01:00", vrf=5,
                          flags=constants.VIF_FLAG_POLICY_ENABLED, nh_idx=38)
        vif3.sync()

        # Add hbs-l in vrf table
        vrf = Vrf(vrf_idx=5)
        vrf.set_vrf_flags(constants.VRF_FLAG_HBS_L_VALID)
        vrf.set_hbfl_vif_idx(vif1.idx())
        vrf.sync()

        # Add hbs-r in vrf table
        vrf = Vrf(vrf_idx=5)
        vrf.set_vrf_flags(constants.VRF_FLAG_HBS_R_VALID)
        vrf.set_hbfr_vif_idx(vif2.idx())
        vrf.sync()

        # Remove hbs-r in vrf table
        vrf = Vrf(vrf_idx=5)
        vrf.set_vrf_flags(constants.VRF_FLAG_HBS_R_VALID)
        vrf.delete_hbfr_vif_idx()
        vrf.sync()

        # Remove hbs-l in vrf table
        vrf = Vrf(vrf_idx=5)
        vrf.set_vrf_flags(constants.VRF_FLAG_HBS_L_VALID)
        vrf.delete_hbfl_vif_idx()
        vrf.sync()

        # Remove vrf entry in vrf table
        vrf = Vrf(vrf_idx=5)
        vrf.delete()

        # Add hbs-l and hbs-r
        vrf = Vrf(vrf_idx=5)
        vrf.set_vrf_flags(constants.VRF_FLAG_HBS_L_VALID | constants.VRF_FLAG_HBS_R_VALID)
        vrf.set_hbfl_vif_idx(vif1.idx())
        vrf.set_hbfr_vif_idx(vif2.idx())
        vrf.sync()

        # Remove vrf entry in vrf table
        vrf = Vrf(vrf_idx=5)
        vrf.delete()
