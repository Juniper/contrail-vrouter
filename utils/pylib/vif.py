#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import os
import sys
import constants
from object_base import *
from vr_py_sandesh.vr_py.ttypes import *
from scapy.all import *


class Vif(ObjectBase, vr_interface_req):
    """Base class to create virtual interfaces"""
    # Index to allocate in case of auto index allocation
    _auto_alloc_idx = 0

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
        if ObjectBase.auto_vif_idx_alloc:
            Vif._auto_alloc_idx += 1
            self.vifr_idx = Vif._auto_alloc_idx
        else:
            self.vifr_idx = idx
        self.h_op = constants.SANDESH_OPER_ADD
        self.vifr_name = name
        if ipv4_str:
            self.vifr_ip = self.vt_ipv4(ipv4_str)
        if mac_str:
            self.vifr_mac = self.vt_mac(mac_str)
        self.vifr_transport = constants.VIF_TRANSPORT_PMD
        if ipv6_str is not None:
            self.vifr_ip6_u, self.vifr_ip6_l = self.vt_ipv6(ipv6_str)
        self.sreq_class = vr_interface_req.__name__

    def __repr__(self):
        """Display basic details of the Vif"""
        return "Vif(idx:{}, name:{})".format(self.vifr_idx, self.vifr_name)

    def __str__(self):
        """Display basic details of the Vif"""
        return "Vif(idx:{}, name:{})".format(self.vifr_idx, self.vifr_name)

    def send_packet(self, tx_pkt_list):
        """Sends a packet in the vif"""
        req_file = self.create_pcap_req(tx_pkt_list, self.vifr_name,
                                        None, None)
        # run the vtest cmd
        self.run_vtest_command(True, req_file)

    def send_and_receive_packet(self, tx_pkt_list, receive_vif, rx_pkt_list):
        """Sends a packet and receive the reply packet"""
        req_file = self.create_pcap_req(tx_pkt_list, self.vifr_name,
                                        rx_pkt_list, receive_vif.vifr_name)
        output_pcap = self.get_output_pcap_file(req_file)
        scapy_cap = None
        if output_pcap:
            scapy_cap = scapy.all.rdpcap(output_pcap)
        if scapy_cap:
            return scapy_cap[0]
        else:
            return None

    def idx(self):
        """Returns vif index"""
        return self.vifr_idx

    def get(self, key):
        """
        Queries vrouter and return the key value from the response xml file
        """
        self.h_op = constants.SANDESH_OPER_GET
        self.vifr_flags = 0
        return super(Vif, self).get(key)

    def get_vif_name(self):
        """
        Queries vrouter and returns vifr_name value from the response xml file
        """
        return self.get('vifr_name').strip('\n')

    def get_vif_idx(self):
        """
        Queries vrouter and returns vifr_idx value from the response xml file
        """
        return int(self.get('vifr_idx'))

    def get_vif_ip(self):
        """
        Queries vrouter and returns vifr_ip value from the response xml file
        """
        return int(self.get('vifr_ip'))

    def get_vif_ipackets(self):
        """
        Queries vrouter and returns vif_ipackets value from the response xml \
        file
        """
        return int(self.get('vifr_ipackets'))

    def get_vif_opackets(self):
        """
        Queries vrouter and returns vif_opackets value from the response xml \
        file
        """
        return int(self.get('vifr_opackets'))


class VirtualVif(Vif):
    """
    VirtualVif class to create virtual vif

    Mandatory Parameters:
    --------------------
    name : str
        Interface name
    ipv4_str : str
        IPv4 address
    mac_str: str
        MAC address
    idx(if auto_alloc is not set) : int
        Interface index

    Optional Parameters:
    -------------------
    ipv6_str : str
        IPv6 address
    nh_idx : str
        Nexthop index
    vrf : int
        Vrf id
    mcast_vrf : int
        Multicast vrf id
    mtu : int
        MTU size
    flags : int
        Vif flags
    """

    def __init__(self,
                 name,
                 ipv4_str,
                 mac_str,
                 idx=0,
                 ipv6_str=None,
                 nh_idx=0,
                 vrf=0,
                 mcast_vrf=65535,
                 mtu=1514,
                 flags=(constants.VIF_FLAG_POLICY_ENABLED |
                        constants.VIF_FLAG_DHCP_ENABLED),
                 **kwargs):
        super(VirtualVif, self).__init__(idx, name, ipv4_str, mac_str,
                                         ipv6_str, **kwargs)
        self.vifr_type = constants.VIF_TYPE_VIRTUAL
        self.vifr_nh_id = nh_idx
        self.vifr_transport = constants.VIF_TRANSPORT_PMD
        self.vifr_vrf = vrf
        self.vifr_mcast_vrf = mcast_vrf
        self.vifr_mtu = mtu
        self.vifr_flags = flags


class AgentVif(Vif):
    """
    AgentVif Class to create agent vif

    Mandatory Parameters:
    --------------------
    idx(if auto_alloc is not set) : int
        Interface index

    Optional Parameters:
    -------------------
    vrf : int
        Vrf id
    mcast_vrf : int
        Multicast vrf id
    mtu : int
        MTU size
    flags : int
        Vif flags
    """

    def __init__(self, idx=0, vrf=65535, mcast_vrf=65535, mtu=1514,
                 flags=0, **kwargs):
        name = 'unix'
        super(AgentVif, self).__init__(idx, name, None, None, None,
                                       **kwargs)
        self.vifr_name = name
        self.vifr_type = constants.VIF_TYPE_AGENT
        self.vifr_transport = constants.VIF_TRANSPORT_SOCKET
        self.vifr_vrf = vrf
        self.vifr_mcast_vrf = mcast_vrf
        self.vifr_mtu = mtu
        self.vifr_mac = self.vt_mac("00:00:5e:00:01:00")
        self.vifr_flags = flags


class VhostVif(Vif):
    """
    VhostVif class to create vhost vif

    Mandatory Parameters:
    --------------------
    ipv4_str : str
        IPv4 address
    mac_str: str
        MAC address
    idx(if auto_alloc is not set) : int
        Interface index

    Optional Parameters:
    -------------------
    ipv6_str : str
        IPv6 address
    nh_idx : str
        Nexthop index
    vrf : int
        Vrf id
    mcast_vrf : int
        Multicast vrf id
    mtu : int
        MTU size
    flags : int
        Vif flags
    """

    def __init__(
            self,
            ipv4_str,
            mac_str,
            ipv6_str=None,
            idx=0,
            nh_idx=None,
            vrf=0,
            mcast_vrf=65535,
            mtu=1514,
            flags=(constants.VIF_FLAG_L3_ENABLED |
                   constants.VIF_FLAG_DHCP_ENABLED),
            **kwargs):
        name = 'vhost0'
        super(VhostVif, self).__init__(idx, name, ipv4_str, mac_str, ipv6_str,
                                       **kwargs)
        self.vifr_type = constants.VIF_TYPE_HOST
        self.vifr_nh_id = nh_idx
        self.vifr_transport = constants.VIF_TRANSPORT_PMD
        self.vifr_vrf = vrf
        self.vifr_mcast_vrf = mcast_vrf
        self.vifr_mtu = mtu
        self.vifr_flags = flags


class FabricVif(Vif):
    """
    FabricVif class to create fabric vif

    Mandatory Parameters:
    --------------------
    name : str
        Interface name
    mac_str: str
        MAC address
    idx(if auto_alloc is not set) : int
        Interface index

    Optional Parameters:
    -------------------
    ipv4_str : str
        IPv4 address
    ipv6_str : str
        IPv6 address
    vrf : int
        Vrf id
    mcast_vrf : int
        Multicast vrf id
    mtu : int
        MTU size
    flags : int
        Vif flags
    """

    def __init__(
            self,
            name,
            mac_str,
            ipv4_str=None,
            ipv6_str=None,
            idx=0,
            vrf=0,
            mcast_vrf=65535,
            mtu=1514,
            flags=constants.VIF_FLAG_VHOST_PHYS,
            **kwargs):
        super(FabricVif, self).__init__(idx, name, ipv4_str, mac_str, ipv6_str,
                                        **kwargs)
        self.vifr_type = constants.VIF_TYPE_PHYSICAL
        self.vifr_flags = flags
        self.vifr_transport = constants.VIF_TRANSPORT_PMD
        self.vifr_vrf = vrf
        self.vifr_mcast_vrf = mcast_vrf
        self.vifr_mtu = mtu
