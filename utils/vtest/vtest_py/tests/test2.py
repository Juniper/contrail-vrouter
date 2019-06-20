#!/usr/bin/python

import sys
import os
sys.path.append(os.getcwd())
from vtest_lib import *

def test2(vt):
    # Add a Vif interface
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

    vt.send_pkt(pkt, "1")
    
    # get the dropstats
    drop_stats = vr_drop_stats_req()
    drop_stats.h_op = 1

    drop_stats_resp = vt.send_sandesh_req(drop_stats, 1)

    invalid_arp = vt.parse_xml_field(drop_stats_resp, "vds_invalid_arp")
    print "Got invalid arp count ", invalid_arp
    if (invalid_arp.find("1") != -1):
        print "Test 2 passed"
        return 0
    else:
        print "Test 2 failed"
        return -1
    
def main():
    vr_path = sys.argv[1]
    vt_path = sys.argv[2]
    sock_dir = sys.argv[3]
    sock_port = sys.argv[4]
    vr = vrouter(vr_path, sock_dir, sock_port)
    vr.run()
    vt = vtest("test2", vt_path, sock_dir, sock_port)
    test2(vt)
    vr.stop()

if __name__ == "__main__":
    main()

