#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import os
import sys
import vtconst
from vtest_object_base import *
from vr_py_sandesh.vr_py.ttypes import *
from scapy.all import *

class Vif(VTestObjectBase, vr_interface_req):
    # Index to allocate in case of auto index allocation
    _auto_alloc_idx = 0

    # name is mandatory
    def __init__(
            self,
            idx,
            name,
            ipv4_str,
            mac_str,
            ipv6_str,
            **kwargs):
        super(Vif, self).__init__()
        vr_interface_req.__init__(self)
        if VTestObjectBase.auto_vif_idx_alloc:
            Vif._auto_alloc_idx += 1
            self.vifr_idx = Vif._auto_alloc_idx
        else:
            self.vifr_idx = idx
        self.h_op = vtconst.SANDESH_OPER_ADD
        self.vifr_name = name
        if ipv4_str:
            self.vifr_ip = self.vt_ipv4(ipv4_str)
        if mac_str:
            self.vifr_mac = self.vt_mac(mac_str)
        self.vifr_transport = vtconst.VIF_TRANSPORT_PMD
        if ipv6_str is not None:
            self.vifr_ip6_u, self.vifr_ip6_l = self.vt_ipv6(ipv6_str)
        self.sreq_class = vr_interface_req.__name__

    # Display basic details of the Vif
    def __repr__(self):
        return "Vif(idx:{}, name:{})".format(self.vifr_idx, self.vifr_name)

    def __str__(self):
        return "Vif(idx:{}, name:{})".format(self.vifr_idx, self.vifr_name)

    def send_packet(self, tx_pkt_list):
        # create the req xml file first
        req_file = self.create_pcap_req(tx_pkt_list, self.vifr_name,
                None, None)
        # run the vtest cmd
        self.run_vtest_command(True, req_file)

    def send_and_receive_packet(self, tx_pkt_list, receive_vif, rx_pkt_list):
        # send packet and receive it on receive_vif
        # create the req xml file
        req_file = self.create_pcap_req(tx_pkt_list, self.vifr_name,
                rx_pkt_list, receive_vif.vifr_name)
        output_pcap = self.get_output_pcap_file(req_file)
        scapy_cap = None
        if output_pcap:
            scapy_cap = scapy.all.rdpcap(output_pcap)
        return scapy_cap

    def idx(self):
        return self.vifr_idx

    def get(self, key):
        self.h_op = vtconst.SANDESH_OPER_GET
        self.vifr_flags = 0
        return super(Vif, self).get(key)

    def get_vif_name(self):
        return self.get('vifr_name').strip('\n')

    def get_vif_idx(self):
        return int(self.get('vifr_idx'))

    def get_vif_ip(self):
        return int(self.get('vifr_ip'))

    def get_vif_ipackets(self):
        return int(self.get('vifr_ipackets'))

    def get_vif_opackets(self):
        return int(self.get('vifr_opackets'))


class VirtualVif(Vif):

    def __init__(self, name, ipv4_str, mac_str, idx=0, ipv6_str=None,
                 nh_id=0, vif_transport=vtconst.VIF_TRANSPORT_PMD, vrf=0,
                 mcast_vrf=65535, mtu=1514,
                 flags=0, **kwargs):
        super(VirtualVif, self).__init__(idx, name, ipv4_str, mac_str,
                                         ipv6_str, **kwargs)
        self.vifr_type = vtconst.VIF_TYPE_VIRTUAL
        self.vifr_nh_id = nh_id
        self.vifr_transport = vif_transport
        self.vifr_vrf = vrf
        self.vifr_mcast_vrf = mcast_vrf
        self.vifr_mtu = mtu
        self.vifr_flags = flags


class AgentVif(Vif):
    def __init__(self, name='unix', idx=0, vrf=65535, mcast_vrf=65535, mtu=1514,
                flags=0, **kwargs):
        super(AgentVif, self).__init__(idx, name, None, None, None,
                                       **kwargs)
        self.vifr_type = vtconst.VIF_TYPE_AGENT
        self.vifr_transport = vtconst.VIF_TRANSPORT_SOCKET
        self.vifr_vrf = vrf
        self.vifr_mcast_vrf = mcast_vrf
        self.vifr_mtu = mtu
        self.vifr_mac = self.vt_mac("00:00:5e:00:01:00")
        self.vifr_flags = flags


class VhostVif(Vif):
    def __init__(
            self,
            ipv4_str,
            mac_str,
            ipv6_str=None,
            name='vhost0',
            idx=0,
            nh_id=None,
            vif_transport=vtconst.VIF_TRANSPORT_PMD,
            vrf=0,
            mcast_vrf=65535,
            mtu=1514,
            flags=0,
            **kwargs):
        super(VhostVif, self).__init__(idx, name, ipv4_str, mac_str, ipv6_str,
                                       **kwargs)
        self.vifr_type = vtconst.VIF_TYPE_HOST
        self.vifr_nh_id = nh_id
        self.vifr_transport = vif_transport
        self.vifr_vrf = vrf
        self.vifr_mcast_vrf = mcast_vrf
        self.vifr_mtu = mtu
        self.vifr_flags=flags


class FabricVif(Vif):
    def __init__(
            self,
            name,
            mac_str,
            ipv4_str=None,
            ipv6_str=None,
            idx=0,
            vif_transport=vtconst.VIF_TRANSPORT_PMD,
            vrf=0,
            mcast_vrf=65535,
            mtu=1514,
            flags=0,
            **kwargs):
        super(FabricVif, self).__init__(idx, name, ipv4_str, mac_str, ipv6_str,
                                        **kwargs)
        self.vifr_type = vtconst.VIF_TYPE_PHYSICAL
        self.vifr_flags = flags
        self.vifr_transport = vif_transport
        self.vifr_vrf = vrf
        self.vifr_mcast_vrf = mcast_vrf
        self.vifr_mtu = mtu
