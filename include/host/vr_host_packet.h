/*
 * vr_host_packet.h -- host representation of packet
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_HOST_PACKET_H__
#define __VR_HOST_PACKET_H__

/*
 * invariably, VR will push headers and it makes sense to have
 * a reasonable header space
 */
#define VR_HPACKET_HEAD_SPACE       64

struct vr_hpacket_pool {
    struct vr_hpacket *pool_head;
};

#define VR_HPACKET_FLAGS_CLONED     0x1

/* host packet representation */
struct vr_hpacket {
    struct vr_hpacket *hp_next;
    struct vr_packet hp_packet;
    /* pointer to the packet buffer */
    unsigned char *hp_head;
    /*
     * the following entries are duplicated from vr_packet since
     * requests to reset the packet to the original state needs
     * the information about the original packet
     */
    unsigned short hp_data;
    unsigned short hp_tail;
    unsigned short hp_end;
    /*
     * total length of this packet and the list of packets that
     * follow this guy
     */
    unsigned short hp_len;
    unsigned int hp_flags;
    /* pool from where this packet came from */
    void *hp_pool;
} __attribute__((packed));

static inline unsigned char *
hpkt_data(struct vr_hpacket *hpkt)
{
    return hpkt->hp_head + hpkt->hp_data;
}

static inline unsigned short
hpkt_size(struct vr_hpacket *hpkt)
{
    return hpkt->hp_end;
}

static inline unsigned char *
hpkt_end(struct vr_hpacket *hpkt)
{
    return hpkt->hp_head + hpkt->hp_end;
}

static inline unsigned short
hpkt_len(struct vr_hpacket *hpkt)
{
    return hpkt->hp_len;
}

static inline unsigned short
hpkt_head_len(struct vr_hpacket *hpkt)
{
    return (hpkt->hp_tail - hpkt->hp_data);
}

#define VR_PACKET_TO_HPACKET(pkt) CONTAINER_OF(hp_packet, struct vr_hpacket, pkt)

/*
 * just to support clone, we need this at the end of the data
 * area of the packet
 */
struct vr_hpacket_tail {
    unsigned int hp_users;
} __attribute__((packed));

int vr_hpacket_copy(unsigned char *, struct vr_hpacket *,
        unsigned int, unsigned int);
void vr_hpacket_free(struct vr_hpacket *);
struct vr_hpacket *vr_hpacket_alloc(unsigned int);
struct vr_hpacket *vr_hpacket_clone(struct vr_hpacket *);
struct vr_hpacket *vr_hpacket_pool_alloc(struct vr_hpacket_pool *);
void vr_hpacket_pool_free(struct vr_hpacket *);
struct vr_hpacket_pool *vr_hpacket_pool_create(unsigned int, unsigned int);
void vr_hpacket_pool_destroy(struct vr_hpacket_pool *);


#endif /* __VR_HOST_PACKET_H__ */
