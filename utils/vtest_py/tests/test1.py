#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
from vtest_lib import *
import vtconst


# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test
def test1(vrouter_test_fixture):

    vt = vtest("test1")

    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 1
    vif.vifr_name = "tap_1"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 0
    vif.vifr_mac = vt_mac("de:ad:be:ef:00:02")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("1.1.1.10")
    vif.vifr_ip6_u = 72340172838076673
    vif.vifr_ip6_l = 18374403900871474942

    # add the vif
    vt.send_sandesh_req(vif)

    # query the vif and see if it really got added
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_GET
    vif.vifr_idx = 1

    vif_resp_file = vt.send_sandesh_req(vif, vt.VT_RESPONSE_REQD)

    # parse the fields and validate the response
    vif_name = vt.parse_xml_field(vif_resp_file, "vifr_name")
    print "Got vif name ", vif_name
    assert (vif_name.find("1") != -1), "Failed to get vif name"
    vif_mtu = vt.parse_xml_field(vif_resp_file, "vifr_mtu")
    print "Got vif mtu ", vif_mtu
    assert (vif_mtu.find("1514") != -1), "Failed to get mtu value"
    print "Test 1 passed"
    return 0


def main():
    test1()


if __name__ == "__main__":
    main()
