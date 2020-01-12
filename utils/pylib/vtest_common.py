#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import ipaddress
import netaddr
import os
import socket
from vtest_base import VTestBase

# Add all utility functions here like vt_ipv4, vt_encap etc.


class VTestCommon(object):
    vif_auto_alloc = False
    nh_auto_alloc = False

    @classmethod
    def htonll(self, val):
        return (socket.htonl(val & 0xFFFFFFFF) << 32) + \
            (socket.htonl(val >> 32))

    @classmethod
    def ntohll(self, val):
        return (socket.ntohl(val & 0xFFFFFFFF) << 32) + \
            (socket.ntohl(val >> 32))

    @classmethod
    def vt_encap(self, str):
        blist = list(str.replace(' ', '').decode('hex'))
        for i in range(len(blist)):
            blist[i] = ord(blist[i])
        return blist

    @classmethod
    def vt_mac(self, str):
        blist = list(str.replace(':', '').decode('hex'))
        for i in range(len(blist)):
            blist[i] = ord(blist[i])
        return blist

    @classmethod
    def vt_ipv4(self, str):
        return socket.htonl(int(ipaddress.IPv4Address(unicode(str))))

    @classmethod
    def vt_ipv4_bytes(self, str):
        ipv4_sp = str.split(".")
        ipv4_dec = []
        for i in range(len(ipv4_sp)):
            ipv4_dec.append(int(ipv4_sp[i]))
        return ipv4_dec

    @classmethod
    def vt_ipv6(self, str):
        ip6_u = int(bin(netaddr.IPAddress(str) >> 64), 2)
        ip6_l = int(bin(netaddr.IPAddress(str) & (1 << 64) - 1), 2)
        return self.htonll(ip6_u), self.htonll(ip6_l)
