/*
 * vr_datapath.h
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_DATAPATH_H__
#define __VR_DATAPATH_H__

#include "vr_packet.h"

static inline bool
well_known_mac(unsigned char *dmac)
{
    unsigned char vr_well_known_mac_infix[] = { 0x80, 0xc2 };
    if (!memcmp(&dmac[VR_ETHER_PROTO_MAC_OFF], vr_well_known_mac_infix,
                            VR_ETHER_PROTO_MAC_LEN)) 
        if (!*dmac || (*dmac == 0x1))
            return true;

    return false;
}

unsigned int vr_virtual_input(unsigned short, struct vr_interface *,
                              struct vr_packet *, unsigned short);
unsigned int vr_fabric_input(struct vr_interface *, struct vr_packet *,
                             unsigned short);

int vr_l3_input(struct vr_packet *, struct vr_forwarding_md *);
int vr_l2_input(struct vr_packet *, struct vr_forwarding_md *);
int vr_arp_input(struct vr_packet *, struct vr_forwarding_md *, int);
int vr_ip_input(struct vrouter *, struct vr_packet *,
                struct vr_forwarding_md *);
int vr_ip6_input(struct vrouter *, struct vr_packet *,
                 struct vr_forwarding_md *);
extern void vr_ip_update_csum(struct vr_packet *, unsigned int, unsigned int);
extern uint16_t vr_icmp6_checksum(void *, unsigned int);

int vr_untag_pkt(struct vr_packet *);
int vr_tag_pkt(struct vr_packet *, unsigned short);
int vr_pkt_type(struct vr_packet *, unsigned short, struct vr_forwarding_md *);

int vr_trap(struct vr_packet *, unsigned short, unsigned short, void *);
extern int vr_forward(struct vrouter *, struct vr_packet *,
                      struct vr_forwarding_md *);

mac_response_t vr_get_l3_stitching_info(struct vr_packet *, struct vr_route_req *,
                         struct vr_forwarding_md *, char *, char *, int , int *);
int vr_handle_mac_response(struct vr_packet *, struct vr_forwarding_md *,
                           mac_response_t , int );


#endif /* __VR_DATAPATH_H__ */
