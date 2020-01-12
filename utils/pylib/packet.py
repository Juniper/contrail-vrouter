#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#
from scapy.all import *


class PacketBase(object):
    def __init__():
        pass


class Packet(PacketBase):
    """Base class for packet"""
    def __init__():
        pass


class EtherPacket(Packet):
    """
    EtherPacket class for creating ethernet packet

    Mandatory Parameters:
    --------------------
    smac : str
        Source mac address
    dmac : str:
        Destination mac address
    ether_type : int
        Ethernet type
    """
    def __init__(self, smac, dmac, ether_type):
        self.eth = None
        if smac and dmac:
            self.eth = Ether(src=smac, dst=dmac, type=ether_type)

    def get_packet(self):
        return self.eth


class ArpPacket(EtherPacket):
    """
    ArpPacket class for creating arp packet

    Mandatory Parameters:
    --------------------
    None (Will just create arp packet without Ethernet header)

    Optional Parameters:
    -------------------
    src : str
        Source mac address
    dst : str:
        Destination mac address
    op : int
       Arp operation code
    hwtype : int
        hardware type
    hwlen : int
        hardware length
    """
    def __init__(
            self,
            src=None,
            dst=None,
            op=1,
            hwtype=0x1,
            hwlen=7,
            **kwargs):
        super(ArpPacket, self).__init__(src, dst, 0x0806, **kwargs)
        self.arp = ARP(op=op, hwtype=hwtype,
                       hwlen=hwlen)

    def get_packet(self):
        if self.eth:
            return self.eth / self.arp
        else:
            return self.arp


class VlanPacket(EtherPacket):
    """
    VlanPacket class for creating vlan packet

    Mandatory Parameters:
    --------------------
    None (Will just create vlan packet without Ethernet header)

    Optional Parameters:
    -------------------
    src : str
        Source mac address
    dst : str:
        Destination mac address
    op : int
       Arp operation 
    hwtype : int
        hwtype
    hwlen : int
        hwlen
    """
    def __init__(
            self,
            src=None,
            dst=None,
            vlan=1,
            **kwargs):
        super(VlanPacket, self).__init__(src, dst, ether_type=0x8100, **kwargs)
        self.vlan = Dot1Q(vlan=vlan)

    def get_packet(self):
        if self.eth:
            return self.eth / self.vlan
        else:
            return self.arp


class IpPacket(EtherPacket):
    """
    IpPacket class for creating IPv4 packet

    Mandatory Parameters:
    --------------------
    proto : str
        IP protocol
    sip : str
        Source IP address
    dip : str:
        Destination IP address

    Optional Parameters:
    -------------------
    smac : str
       Source mac address
    dmac : str
        Destination mac address
    ihl : int
        Internet header length
    id : int
        Identification field
    ttl : int
        Time to live
    """
    def __init__(self, proto, sip, dip, smac=None, dmac=None,
                    ihl=5, id=1, ttl=64, **kwargs):
        super(IpPacket, self).__init__(smac, dmac, 0x800, **kwargs)
        self.ip = IP(version=4, ihl=ihl, id=id,
                     ttl=ttl, proto=proto, dst=dip, src=sip)

    def get_packet(self):
        if self.eth and self.ip:
            return self.eth / self.ip
        else:
            return self.ip

class Ipv6Packet(EtherPacket):
    """
    Ipv6Packet class for creating IPv6 packet

    Mandatory Parameters:
    --------------------
    sipv6 : str
        Source IP address
    dipv6 : str:
        Destination IP address

    Optional Parameters:
    -------------------
    smac : str
       Source mac address
    dmac : str
        Destination mac address
    nh : int
        Next header
    """
    def __init__(self, sipv6, dipv6, smac=None, dmac=None, nh=0, **kwargs):
        super(Ipv6Packet, self).__init__(smac, dmac, 0x86dd, **kwargs)
        self.ipv6 = IPv6(src=sipv6, dst=dipv6, nh=nh, version=6,
                tc=0, fl=0, plen=None, hlim=64)

    def get_packet(self):
        if self.eth and self.ipv6:
            return self.eth / self.ipv6
        else:
            return self.ipv6

class IcmpPacket(IpPacket):
    """
    IcmpPacket class for creating ICMP packet

    Mandatory Parameters:
    --------------------
    sip : str
        Source IP address
    dip : str:
        Destination IP address

    Optional Parameters:
    -------------------
    smac : str
       Source mac address
    dmac : str
        Destination mac address
    icmp_type : int
        Icmp type
    id : int
        Identifier
    """
    def __init__(
            self,
            sip,
            dip,
            smac=None,
            dmac=None,
            icmp_type=8,
            id=1,
            **kwargs):
        super(IcmpPacket, self).__init__(
            'icmp',
            sip,
            dip,
            smac,
            dmac,
            **kwargs)
        self.icmp = ICMP(type=icmp_type, code=0, id=id)

    def get_packet(self):
        if self.eth:
            return self.eth / self.ip / self.icmp
        else:
            return self.ip / self.icmp


class UdpPacket(IpPacket):
    """
    UdpPacket class for creating udp packet

    Mandatory Parameters:
    --------------------
    sip : str
        Source IP address
    dip : str:
        Destination IP address
    sport : int
        Source port
    dport : int
        Destination port

    Optional Parameters:
    -------------------
    smac : str
       Source mac address
    dmac : str
        Destination mac address
    """
    def __init__(self, sip, dip, sport, dport, smac=None, dmac=None, **kwargs):
        super(UdpPacket, self).__init__('udp', sip, dip, smac, dmac, **kwargs)
        self.udp = UDP(sport=sport, dport=dport)

    def get_packet(self):
        pkt = self.eth / self.ip / self.udp
        return pkt


class DnsPacket(UdpPacket):
    """
    DnsPacket class for creating dns packet

    Mandatory Parameters:
    --------------------
    sip : str
        Source IP address
    dip : str:
        Destination IP address
    sport : int
        Source port
    dport : int
        Destination port
    smac : str
       Source mac address
    dmac : str
        Destination mac address
    """
    def __init__(self, sip, dip, sport, dport, smac, dmac, **kwargs):
        super(DnsPacket, self).__init__(
            sip,
            dip,
            sport,
            dport,
            smac,
            dmac,
            **kwargs)
        self.dns = DNS()

    def get_packet(self):
        pkt = self.eth / self.ip / self.udp / self.dns
        return pkt


class GrePacket(IpPacket):
    """
    GrePacket class for creating gre packet

    Mandatory Parameters:
    --------------------
    sip : str
        Source IP address
    dip : str:
        Destination IP address
    sport : int
        Source port
    dport : int
        Destination port

    Optional Parameters:
    -------------------
    smac : str
       Source mac address
    dmac : str
        Destination mac address
    gre_proto : int
        Gre protocol
    gre_version : int
        Gre version
    gre_flags : int
        Gre flags
    """
    def __init__(self, sip, dip, smac=None, dmac=None,
                 gre_proto=0x8847, gre_version=0, gre_flags=0, **kwargs):
        super(GrePacket, self).__init__('gre', sip, dip, smac, dmac, **kwargs)
        self.gre = GRE(proto=gre_proto, version=gre_version, flags=gre_flags)

    def get_packet(self):
        pkt = self.eth / self.ip / self.gre
        return pkt


class MplsPacket(Packet):
    """
    MplsPacket class for creating mpls packet

    Mandatory Parameters:
    --------------------
    label : int
        Mpls label

    Optional Parameters:
    -------------------
    mpls_ttl : str 
        mpls ttl value
    """
    def __init__(self, label, mpls_ttl=64):
        load_contrib("mpls")
        self.mpls = MPLS(label=label, ttl=mpls_ttl)

    def get_packet(self):
        return self.mpls

class MplsoUdpPacket(UdpPacket):
    """
    MplsoUdpPacket class for creating mpls over udp packet

    Mandatory Parameters:
    --------------------
    label : int
        Mpls label
    sip : str
        Source IP address
    dip : str
        Destination IP address
    smac : str
        Source MAC address
    dmac : str
        Destination MAC address
    sport :
        Source port address
    dport:
        Destination port address

    Optional Parameters:
    -------------------
    inner_pkt : any other packet type
        Inner packet
    mpls_ttl : str 
        mpls ttl value
    """
    def __init__(self, label, sip, dip, smac, dmac, sport, dport,
                 inner_pkt=None, mpls_ttl=64, **kwargs):
        super(MplsoUdpPacket, self).__init__(
            sip,
            dip,
            sport,
            dport,
            smac,
            dmac,
            **kwargs)
        load_contrib("mpls")
        self.mpls = MPLS(label=label, ttl=mpls_ttl)
        self.inner_pkt = inner_pkt

    def get_packet(self):
        pkt = self.eth / self.ip / self.udp / self.mpls / self.inner_pkt
        return pkt


class MplsoGrePacket(GrePacket):
    """
    MplsoGrePacket class for creating mpls over gre packet

    Mandatory Parameters:
    --------------------
    label : int
        Mpls label
    sip : str
        Source IP address
    dip : str
        Destination IP address
    smac : str
        Source MAC address
    dmac : str
        Destination MAC address
    sport :
        Source port address
    dport:
        Destination port address

    Optional Parameters:
    -------------------
    inner_pkt : any other packet type
        Inner packet
    mpls_ttl : str 
        mpls ttl value
    """
    def __init__(
            self,
            label,
            sip,
            dip,
            smac,
            dmac,
            inner_pkt=None,
            mpls_ttl=64,
            **kwargs):
        super(MplsoGrePacket, self).__init__(
            sip=sip,
            dip=sip,
            smac=smac,
            dmac=dmac,
            **kwargs)
        load_contrib("mpls")
        self.mpls = MPLS(label=label, ttl=mpls_ttl)
        self.inner_pkt = inner_pkt

    def get_packet(self):
        pkt = self.eth / self.ip / self.gre / self.mpls / self.inner_pkt
        return pkt

class VxlanPacket(UdpPacket):
    """
    VxlanPacket class for creating mpls over Vxlan packet

    Mandatory Parameters:
    --------------------
    vnid : int
        Vxlan network identifier
    sip : str
        Source IP address
    dip : str
        Destination IP address
    smac : str
        Source MAC address
    dmac : str
        Destination MAC address
    sport :
        Source port address
    dport:
        Destination port address

    Optional Parameters:
    -------------------
    inner_pkt : any other packet type
        Inner packet
    """

    def __init__(self, vnid, sip, dip, smac, dmac, sport, dport,
            inner_pkt=None, **kwargs):
        super(VxlanPacket, self).__init__(sip, dip, sport, dport, smac, dmac, **kwargs)
        self.vxlan = VXLAN(vni=vnid, **kwargs)
        self.inner_pkt = inner_pkt

    def get_packet(self):
        pkt = self.eth / self.ip / self.udp / self.vxlan / self.inner_pkt
        return pkt
