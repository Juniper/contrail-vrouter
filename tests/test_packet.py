#!/usr/bin/python
import os
import sys
import unittest
sys.path.append(os.getcwd())
sys.path.append(os.getcwd() + '/lib/')
import vtest_common
from packet import *
import vtconst


class TestPacket(unittest.TestCase, vtest_common.VTestCommon):

    def test_arp_packet(self):
        arp = ArpPacket(src="de:ad:be:ef:00:02", dst="de:ad:be:ef:00:00")
        pkt = arp.get_packet()
        self.assertIsNotNone(pkt)
        pkt.show()

        arp = ArpPacket()
        pkt = arp.get_packet()
        self.assertIsNotNone(pkt)
        pkt.show()

    def test_ip_packet(self):
        ip = IpPacket(proto='udp', sip='1.1.1.4', dip='2.2.2.4',
                      smac='02:88:67:0c:2e:11', dmac='00:00:5e:00:01:00')
        pkt = ip.get_packet()
        self.assertIsNotNone(pkt)
        pkt.show()

        ip = IpPacket(proto='udp', sip='1.1.1.4', dip='2.2.2.4')
        pkt = ip.get_packet()
        self.assertIsNotNone(pkt)
        pkt.show()

    def test_icmp_packet(self):
        icmp = IcmpPacket(
            sip='1.1.1.4',
            dip='2.2.2.4',
            smac='02:88:67:0c:2e:11',
            dmac='00:00:5e:00:01:00',
            id=1136)
        pkt = icmp.get_packet()
        self.assertIsNotNone(pkt)
        pkt.show()

    def test_udp_packet(self):
        udp = UdpPacket(sip='1.1.1.4', dip='2.2.2.4',
                        smac="de:ad:be:ef:00:02", dmac="de:ad:be:ef:00:00",
                        sport=53, dport=60185)
        pkt = udp.get_packet()
        self.assertIsNotNone(pkt)
        pkt.show()

        # udp packet with different ttl value
        udp = UdpPacket(sip='1.1.1.4', dip='2.2.2.4',
                        smac="de:ad:be:ef:00:02", dmac="de:ad:be:ef:00:00",
                        sport=53, dport=60185, ttl=128)
        pkt = udp.get_packet()
        self.assertIsNotNone(pkt)
        pkt.show()

    def test_dns_packet(self):
        dns = DnsPacket(sip='1.1.1.4', dip='2.2.2.4',
                        smac="de:ad:be:ef:00:02", dmac="de:ad:be:ef:00:00",
                        sport=53, dport=60185)
        pkt = dns.get_packet()
        self.assertIsNotNone(pkt)
        pkt.show()

    def test_mpls_packet(self):
        mpls = MplsPacket(label=42)
        pkt = mpls.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

    def test_mpls_over_udp_packet(self):
        icmp_inner = IcmpPacket(sip='2.2.2.3', dip='1.1.1.3', icmp_type=0)
        pkt = icmp_inner.get_packet()
        self.assertIsNotNone(pkt)

        mpls = MplsoUdpPacket(
            label=42,
            sip='8.0.0.3',
            dip='8.0.0.2',
            smac="de:ad:be:ef:00:02",
            dmac="de:ad:be:ef:00:00",
            sport=53363,
            dport=6635,
            inner_pkt=pkt)
        pkt = mpls.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

        icmp_inner = IcmpPacket(
            sip='2.2.2.3',
            dip='1.1.1.3',
            smac='c0:d2:00:06:44:7c',
            dmac='02:c2:23:4c:d0:55',
            icmp_type=0)
        pkt = icmp_inner.get_packet()
        self.assertIsNotNone(pkt)

        mpls = MplsoUdpPacket(
            label=42,
            sip='8.0.0.3',
            dip='8.0.0.2',
            smac="de:ad:be:ef:00:02",
            dmac="de:ad:be:ef:00:00",
            sport=53363,
            dport=6635,
            inner_pkt=pkt)
        pkt = mpls.get_packet()
        pkt.show()
        self.assertIsNotNone(pkt)

    def test_gre_packet(self):
        gre = GrePacket(sip='2.2.2.3', dip='1.1.1.3',
                        smac='c0:d2:00:06:44:7c', dmac='02:c2:23:4c:d0:55')
        pkt = gre.get_packet()
        self.assertIsNotNone(pkt)
        pkt.show()

    def test_mpls_over_gre_packet(self):
        icmp_inner = IcmpPacket(sip='2.2.2.3', dip='1.1.1.3', icmp_type=0)
        pkt = icmp_inner.get_packet()
        self.assertIsNotNone(pkt)

        mpls = MplsoGrePacket(
            label=42,
            sip='8.0.0.3',
            dip='8.0.0.2',
            smac="de:ad:be:ef:00:02",
            dmac="de:ad:be:ef:00:00",
            inner_pkt=pkt)
        pkt = mpls.get_packet()
        self.assertIsNotNone(pkt)
        pkt.show()
