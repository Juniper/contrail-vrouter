#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')

from vtest_lib import *
import vtconst

# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test
def test_vr_logger_2(vrouter_test_fixture):

    vt = vtest("test_vr_logger_2")
    
    vmi = VIF(1, "tap_1", vt_ipv4("1.1.1.10"), vt_mac("de:ad:be:ef:00:02"))
    vmi.vifr_ip6_u = 72340172838076673
    vmi.vifr_ip6_l = 18374403900871474942
 
    vt.send_sandesh_req(vmi)

    log_idx = 0
    cur_idx = -1
    vr_log = vr_log_req()
    vr_log.h_op = vtconst.SANDESH_OPER_GET 
    vr_log.vdl_rid = 0
    vr_log.vdl_module = 1
    vr_log.vdl_level = 3
    vr_log.vdl_log_idx = log_idx
    vr_log.vdl_cur_idx = cur_idx
    vr_log.vdl_clear_buf = 0
    vr_log.vdl_log_buf_en = 1
    
    vrlog_resp_file = vt.send_sandesh_req(vr_log, vt.VT_RESPONSE_REQD)
     
    #parse the fields and validate the response
    vr_log = vt.parse_xml_field(vrlog_resp_file, "vdl_vr_log")
    vr_log_str = ""
    i = 1
    while(i < len(vr_log)):
        if(vr_log[i] == '0'):
            i = i+2
            continue
        vr_log_str = vr_log_str + chr(int(vr_log[i:i+2], 16))
        i = i+3
    print "Got vr_log ", vr_log_str
    comp_str = "Level:info vrf:0 mtu:1514 transp:2 rid:0 nh:0 vif:tap_1"
    assert((comp_str in vr_log_str)), "Failed to get matching vr_log"
    return 0
