#!usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')

from vtest_lib import *
import vtconst

def test_vr_logger_3_1(vrouter_test_fixture):

    vt = vtest("test_vr_logger_3_1")

    vr_conf = vr_logger_conf()
    vr_conf.vlc_logger_en = 1;
    vr_conf.h_op = vtconst.SANDESH_OPER_ADD
    vr_conf.vlc_rid = 0
    vr_conf.vlc_module = 2
    vr_conf.vlc_log_mod_level = [0, 4, 3, 4, 4, 4, 4]
    vr_conf.vlc_log_mod_type = 0
    vt.send_sandesh_req(vr_conf)
    vr_conf.h_op = vtconst.SANDESH_OPER_GET
    vrconf_resp_file = vt.send_sandesh_req(vr_conf, vt.VT_RESPONSE_REQD);

    vrconf_mod_lev = vt.parse_xml_field(vrconf_resp_file, "vlc_log_mod_level")
    print vrconf_resp_file
    assert((vrconf_mod_lev[2*(vr_conf.vlc_module + 1)] == '3')), "Failed to change log level"
    return 0

def test_vr_logger_3_2(vrouter_test_fixture):

    vt = vtest("test_vr_logger_3_2")

    vr_conf = vr_logger_conf()
    vr_conf.vlc_logger_en = 1
    vr_conf.h_op = vtconst.SANDESH_OPER_ADD
    vr_conf.vlc_rid = 0
    vr_conf.vlc_module = 1
    vr_conf.vlc_level = 1
    tmp_array = []
    for i in range(0, 35):
        tmp_array.append(0)
    vr_conf.vlc_log_mod_len = tmp_array
    vr_conf.vlc_log_mod_len[vr_conf.vlc_module*5 + vr_conf.vlc_level] = 100000
    vr_conf.vlc_log_mod_type = 0

    vt.send_sandesh_req(vr_conf)

    vr_conf.h_op = vtconst.SANDESH_OPER_GET
    vrconf_resp_file = vt.send_sandesh_req(vr_conf, vt.VT_RESPONSE_REQD)

    vrconf_mod_len = vt.parse_xml_field(vrconf_resp_file, "vlc_log_mod_len")
    vrconf_mod_len_arr = vrconf_mod_len.split('\n')

    assert((vrconf_mod_len_arr[(vr_conf.vlc_module*5 + vr_conf.vlc_level) + 1]) == '100000'), "Failed to change log size"
    return 0

    return 0
