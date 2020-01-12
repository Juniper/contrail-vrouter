#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import ipaddress
import netaddr
import os
import socket
from base import Base

# Add all utility functions here like vt_ipv4, vt_encap etc.


class Common(object):
    """Class for all utility functions like vt_ipv4, vt_encap etc"""

    @classmethod
    def htonll(self, val):
        """Takes host byte order and returns the network byte order"""
        return (socket.htonl(val & 0xFFFFFFFF) << 32) + \
            (socket.htonl(val >> 32))

    @classmethod
    def ntohll(self, val):
        """Takes network byte order and returns the host byte order"""
        return (socket.ntohl(val & 0xFFFFFFFF) << 32) + \
            (socket.ntohl(val >> 32))

    @classmethod
    def vt_encap(self, str):
        """Returns a list from encap hex string value"""
        blist = list(str.replace(' ', '').decode('hex'))
        for i in range(len(blist)):
            blist[i] = ord(blist[i])
        return blist

    @classmethod
    def vt_mac(self, str):
        """Returns list from mac string"""
        blist = list(str.replace(':', '').decode('hex'))
        for i in range(len(blist)):
            blist[i] = ord(blist[i])
        return blist

    @classmethod
    def vt_ipv4(self, str):
        """Returns unsigned int value for corresponding ipv4 string"""
        return socket.htonl(int(ipaddress.IPv4Address(unicode(str))))

    @classmethod
    def vt_ipv4_bytes(self, str):
        """Returns decimal list for corresponding ipv4 string"""
        ipv4_sp = str.split(".")
        ipv4_dec = []
        for i in range(len(ipv4_sp)):
            ipv4_dec.append(int(ipv4_sp[i]))
        return ipv4_dec

    @classmethod
    def vt_ipv6(self, str):
        """Returns ipv6 upper and lower value from ipv6 string"""
        ip6_u = int(bin(netaddr.IPAddress(str) >> 64), 2)
        ip6_l = int(bin(netaddr.IPAddress(str) & (1 << 64) - 1), 2)
        return self.htonll(ip6_u), self.htonll(ip6_l)
