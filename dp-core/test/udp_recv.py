#! /usr/bin/env python
from scapy.all import *
IFF_TAP   = 0x0002
TUNSETIFF = 0x400454ca
l2_type=0x000
f = os.open("/dev/net/tun", os.O_RDWR)
ioctl(f, TUNSETIFF, struct.pack("16sH","tap3001", IFF_TAP))

while (l2_type!=0x800):
	raw_buf=os.read(f,1500)
	ether=Ether(raw_buf[4:])
	l2_type=ether.type

ip=ether.payload
udp=ip.payload
data=udp.payload
os.close(f)

fd=os.open("/var/tmp/tap3001",os.O_CREAT|os.O_WRONLY);
os.write(fd,str(data));
os.close(fd)
exit()
