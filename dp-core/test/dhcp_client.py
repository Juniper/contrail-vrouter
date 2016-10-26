#! /usr/bin/env python
from scapy.all import *

srcmac=sys.argv[1]
tap_name=sys.argv[2]

IFF_TAP   = 0x0002
TUNSETIFF = 0x400454ca

dhcp_pkt=Ether(src=srcmac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=srcmac)/DHCP(options=[("message-type","discover"),"end"])
dhcp_pkt.show2()
eth_sent_frame="\x00\x00\x00\x00" + str(dhcp_pkt)
f = os.open("/dev/net/tun", os.O_RDWR)
ioctl(f, TUNSETIFF, struct.pack("16sH",tap_name, IFF_TAP))
os.write(f,eth_sent_frame)
os.close(f)
exit()
