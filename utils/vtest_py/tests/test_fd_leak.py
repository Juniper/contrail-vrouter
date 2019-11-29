#!/usr/bin/python

import os
import sys
import ipaddress
import socket
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib')
import vtconst
from vtest_lib import *

@pytest.mark.skip(reason="failing because of vr_uvh_cl_timer_setup() not setup")
def test_fd_leak(vrouter_test_fixture):

    vt = vtest("test_fd_leak")

    pid_cmd = 'pidof contrail-vrouter-dpdk'
    pid = os.popen(pid_cmd).read()
    print "pid = " + str(pid)

    fd_count_cmd = "ls -al /proc/" + str(pid).strip()+ "/fd | wc -l"
    print "fd_count_cmd = " + fd_count_cmd
    orig_fd_count = int(os.popen(fd_count_cmd).read())
    print "orig_fd_count=" + str(orig_fd_count)

    # Add tap vif
    vif = vr_interface_req()
    vif.h_op = vtconst.SANDESH_OPER_ADD
    vif.vifr_type = vtconst.VIF_TYPE_VIRTUAL
    vif.vifr_idx = 5
    vif.vifr_mcast_vrf = 5
    vif.vifr_name = "tapc2234cd0-55"
    vif.vifr_transport = vtconst.VIF_TRANSPORT_PMD
    vif.vifr_vrf = 5
    vif.vifr_mac = vt_mac("00:00:5e:00:01:00")
    vif.vifr_mtu = 1514
    vif.vifr_ip = vt_ipv4("1.1.1.3")
    vif.vifr_nh_id = 38
    vif.vifr_flags = vtconst.VIF_FLAG_POLICY_ENABLED | vtconst.VIF_FLAG_DHCP_ENABLED

    vt.send_sandesh_req(vif)

    eth = Ether(dst='02:e7:03:ea:67:f1', src='02:c2:23:4c:d0:55', type=0x800)
    ip = IP(version=4, ihl=5, id=1, ttl=64, proto='icmp', src='1.1.1.3', dst='1.1.1.5')
    icmp = ICMP(type=8, code=0, id=4145)
    pkt = eth/ip/icmp
    pkt.show()

    # send packet
    vt.send_pkt(pkt, "tapc2234cd0-55")

    new_fd_count = int(os.popen(fd_count_cmd).read())
    print "new_fd_count=" + str(new_fd_count)

    assert (orig_fd_count == new_fd_count)
