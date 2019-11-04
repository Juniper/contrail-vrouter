#!/usr/bin/python

import os
import sys
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')

from test_vtest_common import *
import vtconst
import pytest
import inspect



class TestClass(vTestCommon, object):
    @classmethod
    def setup_method(cls, method):
        super(TestClass, cls).setUpClass(method)

    @classmethod
    def teardown_method(cls, method):
        super(TestClass, cls).tearDownClass(method)

    def test_vm_to_fabric_tx(self):
        uf = util_functions()
        vif = uf.create_vif(
            0,
            0,
            "eth1",
            None,
            None,
            vt_mac("00:1b:21:bb:f9:48"),
            vtconst.VIF_FLAG_VHOST_PHYS,
            type=vtconst.VIF_TYPE_PHYSICAL)
        uf.send_sandesh_req(vif)

        vif = uf.create_vif(
            1,
            0,
            "vhost0",
            None,
            vt_ipv4("8.0.0.2"),
            vt_mac("00:1b:21:bb:f9:48"),
            vtconst.VIF_FLAG_L3_ENABLED | vtconst.VIF_FLAG_DHCP_ENABLED,
            type=vtconst.VIF_TYPE_HOST)
        uf.send_sandesh_req(vif)

        vif = uf.create_vif(
            2,
            65535,
            "unix",
            0,
            0,
            vt_mac("00:00:5e:00:01:00"),
            vtconst.VIF_FLAG_L3_ENABLED,
            type=vtconst.VIF_TYPE_AGENT,
            transport=vtconst.VIF_TRANSPORT_SOCKET)
        uf.send_sandesh_req(vif)

        vif = uf.create_vif(
            5,
            5,
            "tapc2234cd0-55",
            38,
            vt_ipv4("1.1.1.3"),
            vt_mac("00:00:5e:00:01:00"),
            vtconst.VIF_FLAG_POLICY_ENABLED | vtconst.VIF_FLAG_DHCP_ENABLED,
            mcast_vrf=5)
        uf.send_sandesh_req(vif)

        e_nh = uf.create_encap_nh(
            38,
            5,
            vt_encap("02 c2 23 4c d0 55 00 00 5e 00 01 00 08 00"),
            5,
            socket.AF_INET,
            vtconst.NH_FLAG_VALID | vtconst.NH_FLAG_POLICY_ENABLED)
        uf.send_sandesh_req(e_nh)

        t_nh = uf.create_tunnel_nhv4(
            21,
            0,
            vt_encap("00 1b 21 bb f9 46 00 1b 21 bb f9 48 08 00"),
            0,
            vt_ipv4("8.0.0.2"),
            vt_ipv4("8.0.0.3"),
            vtconst.NH_FLAG_VALID | vtconst.NH_FLAG_TUNNEL_UDP_MPLS | vtconst.NH_FLAG_ETREE_ROOT)
        uf.send_sandesh_req(t_nh)

        b_rt = uf.create_bridge_rt(
            5,
            21,
            vt_mac("02:e7:03:ea:67:f1"),
            27,
            vtconst.VR_RT_LABEL_VALID_FLAG | vtconst.VR_RT_ARP_PROXY_FLAG | vtconst.VR_BE_FLOOD_DHCP_FLAG)
        uf.send_sandesh_req(b_rt)

        fl = uf.create_flow(-1,
                            5,
                            vt_ipv4("1.1.1.3"),
                            0,
                            vt_ipv4("1.1.1.5"),
                            0,
                            socket.AF_INET,
                            vtconst.VR_FLOW_ACTION_FORWARD,
                            vtconst.VR_IP_PROTO_ICMP,
                            socket.htons(4145),
                            0,
                            -1,
                            vtconst.VR_FLOW_FLAG_ACTIVE,
                            38,
                            38,
                            -1,
                            0,
                            vt_ipv4("1.1.1.5"),
                            0,
                            vt_ipv4("1.1.1.3"),
                            21,
                            socket.htons(4145))

        add_reverse_flow_and_update(fl)

        eth = Ether(
            dst='02:e7:03:ea:67:f1',
            src='02:c2:23:4c:d0:55',
            type=0x800)
        ip = IP(
            version=4,
            ihl=5,
            id=1,
            ttl=64,
            proto='icmp',
            src='1.1.1.3',
            dst='1.1.1.5')
        icmp = ICMP(type=8, code=0, id=4145)
        pkt = eth / ip / icmp
        pkt.show()

        # send packet
        uf.send_pkt(pkt, "tapc2234cd0-55")

        # Check if the packet was sent to tenant vif
        vif = vr_interface_req()
        vif.h_op = vtconst.SANDESH_OPER_GET
        vif.vifr_idx = 0
        #vif = uf.create_vif(0, None, None, None, None, None, None, None, None, h_op=vtconst.SANDESH_OPER_GET)
        vif_resp_file = uf.send_sandesh_req(vif, uf.VT_RESPONSE_REQD)
        vif_opackets = uf.parse_xml_field(vif_resp_file, "vifr_opackets")
        assert (vif_opackets.find("1") != -1), "Failed to receive NATed packet"
