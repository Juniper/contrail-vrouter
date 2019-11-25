#!/usr/bin/python

import os
import sys
import ipaddress
import socket
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
from vtest_lib import *
import vtconst

def test_vrf_table(vrouter_test_fixture):

    vt = vtest("test_vrf_table")

   # Add hbs-l vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 3
    vif.vifr_name = "tap1589a2b3-22"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_flags = vtconst.VIF_FLAG_POLICY_ENABLED | vtconst.VIF_FLAG_HBS_LEFT
    vif.vifr_vrf = 3
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("100.100.100.4")

    vt.send_sandesh_req(vif)

    # Add hbs-r vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 4
    vif.vifr_name = "tap8b05a86b-36"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_flags = vtconst.VIF_FLAG_POLICY_ENABLED | vtconst.VIF_FLAG_HBS_RIGHT
    vif.vifr_vrf = 4
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("200.200.200.4")

    vt.send_sandesh_req(vif)

    # Add tenant vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 5
    vif.vifr_name = "tapc2234cd0-55"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 5
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("1.0.0.3")
    vif.vifr_flags = vtconst.VIF_FLAG_POLICY_ENABLED
    vif.vifr_nh_id = 38

    vt.send_sandesh_req(vif)

    # Add hbs-l
    vrf = vr_vrf_req()
    vrf.h_op = vtconst.SANDESH_OPER_ADD
    vrf.vrf_rid = 0
    vrf.vrf_idx = 5
    vrf.vrf_flags = vtconst.VRF_FLAG_HBS_L_VALID
    vrf.vrf_hbfl_vif_idx = 3

    vt.send_sandesh_req(vrf)

    # Add hbs-r in vrf table
    vrf = vr_vrf_req()
    vrf.h_op = vtconst.SANDESH_OPER_ADD
    vrf.vrf_rid = 0
    vrf.vrf_idx = 5
    vrf.vrf_flags = vtconst.VRF_FLAG_HBS_R_VALID
    vrf.vrf_hbfr_vif_idx = 4

    vt.send_sandesh_req(vrf)

    # Remove hbs-r in vrf table
    vrf = vr_vrf_req()
    vrf.h_op = vtconst.SANDESH_OPER_ADD
    vrf.vrf_rid = 0
    vrf.vrf_idx = 5
    vrf.vrf_flags = vtconst.VRF_FLAG_HBS_R_VALID
    vrf.vrf_hbfr_vif_idx = -1 

    vt.send_sandesh_req(vrf)

    # Remove hbs-l in vrf table
    vrf = vr_vrf_req()
    vrf.h_op = vtconst.SANDESH_OPER_ADD
    vrf.vrf_rid = 0
    vrf.vrf_idx = 5
    vrf.vrf_flags = vtconst.VRF_FLAG_HBS_L_VALID
    vrf.vrf_hbfl_vif_idx = -1 

    vt.send_sandesh_req(vrf)

    # Remove vrf entry in vrf table
    vrf = vr_vrf_req()
    vrf.h_op = vtconst.SANDESH_OPER_DEL
    vrf.vrf_rid = 0
    vrf.vrf_idx = 5

    vt.send_sandesh_req(vrf)

    # Add hbs-l and hbs-r
    vrf = vr_vrf_req()
    vrf.h_op = vtconst.SANDESH_OPER_ADD
    vrf.vrf_rid = 0
    vrf.vrf_idx = 5
    vrf.vrf_flags = vtconst.VRF_FLAG_HBS_L_VALID |\
                    vtconst.VRF_FLAG_HBS_R_VALID
    vrf.vrf_hbfl_vif_idx = 3
    vrf.vrf_hbfr_vif_idx = 4

    vt.send_sandesh_req(vrf)

    # Remove vrf entry in vrf table
    vrf = vr_vrf_req()
    vrf.h_op = vtconst.SANDESH_OPER_DEL
    vrf.vrf_rid = 0
    vrf.vrf_idx = 5

    vt.send_sandesh_req(vrf)
