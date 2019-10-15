#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')

from vtest_lib import *
import vtconst

# anything with *test* will be assumed by pytest as a test
# The vrouter_test_fixture is passed as an argument to the test
def test_vr_logger_1(vrouter_test_fixture):

    vt = vtest("test_vr_logger_1")
    
    for x in range(0, 3000):
        route = vr_route_req()
        route.h_op = vtconst.SANDESH_OPER_ADD
        route.rtr_family = 2
        route.rtr_nh_id = x+1
        route.rtr_prefix = [0x02, 0x02, 0x01, 0x01]
        route.rtr_prefix_len = 32
        route.rtr_vrf_id = 0
        #Add Route
        vt.send_sandesh_req(route)
    
    log_idx = 0
    cur_idx = -1
    id = 1001
    while(True):
        vr_log = vr_log_req()
        vr_log.h_op = vtconst.SANDESH_OPER_GET 
        vr_log.vdl_rid = 0
        vr_log.vdl_module = 5
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
        log_idx = int(vt.parse_xml_field(vrlog_resp_file, "vdl_log_idx"))
        cur_idx = int(vt.parse_xml_field(vrlog_resp_file, "vdl_cur_idx"))
        vr_log_str_arr = vr_log_str.split("\n")
        for log in vr_log_str_arr:
            if(log == '\x00'):
                continue
            comp_str = ("Level:info OP: 0 family: 2 rid: 0 label: 0 nh_id: %d Err code: -2 prefix:2.2.1.1") %(id)
            assert((comp_str in log)), "Failed to get matching vr_log"
            id += 1
        if (log_idx == cur_idx):
            break
    return 0
