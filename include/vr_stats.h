
#ifndef __VR_STATS_H__
#define __VR_STATS_H__
#define NO_FILTER_REGISTERED 1
struct vr_registered_tuple {
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	unsigned char protocol;
	unsigned short vrf;
};
void set_pkt_filter(struct vrouter *router, struct vr_packet *pkt, short vrf);
#endif
