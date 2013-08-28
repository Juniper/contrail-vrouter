/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_MCAST_H__
#define __VR_MCAST_H__

#define MCAST_INDEX_LEN 12
#define MCAST_HASH_SIZE (0x1 << MCAST_INDEX_LEN)

#define MCAST_IP                        (0xE0000000)
#define MCAST_SSM_IP                    (0xE8000000)
#define MCAST_IP_MASK                   (0xF0000000)
#define MCAST_LINK_LOCAL_IP_MASK        (0xFFFFFF00)

#define IS_LINK_LOCAL_IP(ip) \
        ((ntohl(ip) & METADATA_IP_MASK) == METADATA_IP_SUBNET)

#define IS_BMCAST_IP(ip) \
        (((ntohl(ip) & MCAST_IP_MASK) == MCAST_IP) || (ip == 0xFFFFFFFF)) 

#define IS_MCAST_LINK_LOCAL(ip) \
        (((ntohl(ip) & MCAST_LINK_LOCAL_IP_MASK)) == MCAST_IP)

#define IS_MCAST_SOURCE_SPECFIC(ip) \
        (((ntohl(ip) & MCAST_IP_MASK)) == MCAST_SSM_IP)

#define IS_BCAST_IP(ip) \
        (ip == 0xFFFFFFFF)

unsigned int vr_mcast_forward(struct vrouter *, unsigned short,
        struct vr_packet *, struct vr_forwarding_md *);
    

#endif /* __VR_MCAST_H__ */
