#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#
from scapy.all import *


class VtestPacketBase(object):
    def __init__():
        pass


class VtestPacket(VtestPacketBase):
    def __init__():
        pass


class EtherPacket(VtestPacket):
    def __init__(self, smac, dmac, ether_type):
        self.eth = None
        if smac and dmac:
            self.eth = Ether(src=smac, dst=dmac, type=ether_type)

    def get_packet(self):
        return self.eth


class ArpPacket(EtherPacket):
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


class IpPacket(EtherPacket):
    def __init__(self, proto, sip, dip, smac=None, dmac=None,
                 version=4, ihl=5, id=1, ttl=64, **kwargs):
        super(IpPacket, self).__init__(smac, dmac, 0x800, **kwargs)
        self.ip = IP(version=version, ihl=ihl, id=id,
                     ttl=ttl, proto=proto, dst=dip, src=sip)

    def get_packet(self):
        if self.eth and self.ip:
            return self.eth / self.ip
        else:
            return self.ip


class IcmpPacket(IpPacket):
    def __init__(
            self,
            sip,
            dip,
            smac=None,
            dmac=None,
            icmp_type=8,
            id=1,
            **kwargs):
        super(
            IcmpPacket,
            self).__init__(
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
    def __init__(self, sip, dip, sport, dport, smac=None, dmac=None, **kwargs):
        super(UdpPacket, self).__init__('udp', sip, dip, smac, dmac, **kwargs)
        self.udp = UDP(sport=sport, dport=dport)

    def get_packet(self):
        pkt = self.eth / self.ip / self.udp
        return pkt


class DnsPacket(UdpPacket):
    def __init__(self, sip, dip, sport, dport, smac, dmac, **kwargs):
        super(
            DnsPacket,
            self).__init__(
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
    def __init__(self, sip, dip, smac=None, dmac=None,
                 gre_proto=0x8847, gre_version=0, gre_flags=0, **kwargs):
        super(GrePacket, self).__init__('gre', sip, dip, smac, dmac, **kwargs)
        self.gre = GRE(proto=gre_proto, version=gre_version, flags=gre_flags)

    def get_packet(self):
        pkt = self.eth / self.ip / self.gre
        return pkt


class MplsPacket(VtestPacket):
    def __init__(self, label, mpls_ttl=64):
        load_contrib("mpls")
        self.mpls = MPLS(label=label, ttl=mpls_ttl)

    def get_packet(self):
        return self.mpls


class VxlanPacket(UdpPacket):
    def __init__():
        pass


class MplsoUdpPacket(UdpPacket):
    def __init__(self, label, sip, dip, smac, dmac, sport, dport,
                 inner_pkt=None, mpls_ttl=64, **kwargs):
        super(
            MplsoUdpPacket,
            self).__init__(
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
        super(
            MplsoGrePacket,
            self).__init__(
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
