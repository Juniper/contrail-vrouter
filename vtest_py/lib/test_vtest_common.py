#!/usr/bin/python

import os
import sys

from test_case import *
import vtconst


class vTestCommon(util_functions, object):
    @classmethod
    def setUpClass(self, method):
        super(vTestCommon, self).setUpClass(method)

    @classmethod
    def tearDownClass(self, method):
        super(vTestCommon, self).tearDownClass(method)


"""class topology1(vTestCommon, object):
    @classmethod
    def form_basic_vif(self):
       uf = util_functions()
       vif1 = uf.create_vif(1, "tap_1", vt_ipv4('1.1.1.10'), 0, 0, vt_mac('de:ad:be:ef:00:02'), 0, ip6_u=72340172838076673, ip6_l=18374403900871474942)
       print vif1
       return vif1

    @classmethod
    def form_basic_encap_nh(self):
        util_funcs = util_functions()
        nh1 = util_funcs.create_nh(1, 0, 1, vt_encap("de ad be ef 00 02 de ad be ef 00 01 08 00"), 0, family=vtconst.AF_INET)
        return nh1"""
