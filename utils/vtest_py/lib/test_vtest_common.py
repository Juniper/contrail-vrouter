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

def add_reverse_flow_and_update(fl):
    uf = util_functions()
    resp_file = uf.send_sandesh_req(fl, uf.VT_RESPONSE_REQD)
    fr_indx = uf.parse_xml_field(resp_file, "fresp_index")
    fr_genid = uf.parse_xml_field(resp_file, "fresp_gen_id")

    rfl = uf.create_flow(-1, 5, vt_ipv4("1.1.1.5"), 0, vt_ipv4("1.1.1.3"), 0, socket.AF_INET, vtconst.VR_FLOW_ACTION_FORWARD, vtconst.VR_IP_PROTO_ICMP, socket.htons(4145), 0, int(fr_indx), vtconst.VR_FLOW_FLAG_ACTIVE | vtconst.VR_RFLOW_VALID, 38, 21, -1, 0, vt_ipv4("1.1.1.3"), 0, vt_ipv4("1.1.1.5"), 21, socket.htons(4145))

    resp_file = uf.send_sandesh_req(rfl, uf.VT_RESPONSE_REQD)

    rfr_indx = uf.parse_xml_field(resp_file, "fresp_index")

    fl.fr_index = int(fr_indx)
    fl.fr_rindex = int(rfr_indx)
    fl.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE | vtconst.VR_RFLOW_VALID
    fl.fr_gen_id = int(fr_genid)

    resp_file = uf.send_sandesh_req(fl, uf.VT_RESPONSE_REQD)

    fr_indx = uf.parse_xml_field(resp_file, "fresp_index")

class topology(vTestCommon, object):
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
        return nh1


