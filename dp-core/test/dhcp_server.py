#! /usr/bin/env python
from scapy.all import *

IFF_TAP   = 0x0002
TUNSETIFF = 0x400454ca
l2_type=0x000

f = os.open("/dev/net/tun", os.O_RDWR)
ioctl(f, TUNSETIFF, struct.pack("16sH","pkt0", IFF_TAP))

while (l2_type!=0x800):
	raw_buf=os.read(f,1500)
	ether=Ether(raw_buf[4:])
	l2_type=ether.type


ether=Ether(raw_buf[32:])
sport=((ether.payload).payload).sport
dport=((ether.payload).payload).dport
os.close(f)

if sport==68 and  dport==67 :
	fd=os.open("/var/tmp/pkt0",os.O_CREAT|os.O_WRONLY);
	os.write(fd,"DHCPDISCOVER");
	os.close(fd)

exit()
