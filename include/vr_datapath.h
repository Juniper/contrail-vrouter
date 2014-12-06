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
int vr_arp_input(unsigned short, struct vr_packet *, struct vr_forwarding_md *);
int vr_trap(struct vr_packet *, unsigned short ,
        unsigned short , void *);
int vr_l3_input(unsigned short , struct vr_packet *,
                              struct vr_forwarding_md *);
unsigned int vr_l2_input(unsigned short , struct vr_packet *,
                              struct vr_forwarding_md *);
int vr_pkt_type(struct vr_packet *, unsigned short);
bool vr_l3_well_known_packet(unsigned short , struct vr_packet *);
int vr_trap_l2_well_known_packets(unsigned short , struct vr_packet *,
                                  struct vr_forwarding_md *);
int vr_tor_input(unsigned short , struct vr_packet *, 
                 struct vr_forwarding_md *);

int vr_untag_pkt(struct vr_packet *);
int vr_tag_pkt(struct vr_packet *, unsigned short );
int vr_get_l3_hdr_offset_from_eth(struct vr_eth *, int , unsigned short *);


#endif //__VR_DATAPATH_H__
