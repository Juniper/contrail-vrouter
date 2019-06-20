#!/usr/bin/python

import sys
import os
sys.path.append(os.getcwd())
from vtest_lib import *

def test1(vt):
    vif = vr_interface_req()
    vif.h_op = 0
    vif.vifr_type = 3
    vif.vifr_idx = 1
    vif.vifr_name = "1"
    vif.vifr_transport = 2
    vif.vifr_vrf = 0
    vif.vifr_mac = [ 0xde, 0xad, 0xbe, 0xef, 0x00, 0x02]
    vif.vifr_mtu = 1514
    vif.vifr_ip = 16843018
    vif.vifr_ip6_u = 72340172838076673
    vif.vifr_ip6_l = 18374403900871474942
    
    # add the vif
    vt.send_sandesh_req(vif)

    # query the vif and see if it really got added
    vif = vr_interface_req()
    vif.h_op = 1
    vif.vifr_idx = 1

    vif_resp_file = vt.send_sandesh_req(vif, 1)

    # parse the fields and validate the response
    vif_name = vt.parse_xml_field(vif_resp_file, "vifr_name")
    print "Got vif name ", vif_name
    if (vif_name.find("1") != -1):
        print "Got correct vif name"
    else:
        print "Failed to get vif name"
        return -1
    vif_mtu = vt.parse_xml_field(vif_resp_file, "vifr_mtu")
    print "Got vif mtu ", vif_mtu
    if (vif_mtu.find("1514") != -1):
        print "Got correct mtu value"
    else:
        print "Failed to get mtu value"
        return -1
    print "Test 1 passed"
    return 0

def main():
    vr_path = sys.argv[1]
    vt_path = sys.argv[2]
    sock_dir = sys.argv[3]
    sock_port = sys.argv[4]
    vr = vrouter(vr_path, sock_dir, sock_port)
    vr.run()
    vt = vtest("test1", vt_path, sock_dir, sock_port)
    test1(vt)
    vr.stop()

if __name__ == "__main__":
    main()

