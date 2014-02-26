#! /usr/bin/env python
from scapy.all import *

srcmac=sys.argv[1]
dstmac="11:22:33:44:55:66"
srcip=sys.argv[2]
dstip=sys.argv[3]
tap_name=sys.argv[4]

srcport=30000
dstport=30000

IFF_TAP   = 0x0002
TUNSETIFF = 0x400454ca

udp=UDP(sport=srcport,dport=dstport)
ip=IP(src=srcip,dst=dstip)
ether=Ether(src=srcmac,dst=dstmac,type=0x800)
l3_pkt=ip/udp/"sachin"
l3_pkt.show2()
eth_frame = str(ether) + str(l3_pkt)
eth_sent_frame="\x00\x00\x00\x00" + str(eth_frame)

f = os.open("/dev/net/tun", os.O_RDWR)
ioctl(f, TUNSETIFF, struct.pack("16sH",tap_name, IFF_TAP))
os.write(f,eth_sent_frame)
os.close(f)
exit()
