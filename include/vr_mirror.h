/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_MIRROR_H__
#define __VR_MIRROR_H__

#define VR_MAX_MIRROR_INDICES           255

#define VR_MIRROR_FLAG_DYNAMIC          0x1


struct vrouter;
struct vr_packet;

typedef enum {
    MIRROR_TYPE_UNKNOWN,
    MIRROR_TYPE_PORT_RX,
    MIRROR_TYPE_PORT_TX,
    MIRROR_TYPE_ACL,
    MIRROR_TYPE_MAX
} mirror_type_t;

/* Mirror packet can be either MPLSoGre or MPLSoUDP. Lets calculate the
 * highest for head space */
#define VR_MIRROR_PKT_HEAD_SPACE    (sizeof(struct vr_pcap) + \
        sizeof(struct vr_udp) + sizeof(struct vr_ip6) + \
        VR_MPLS_HDR_LEN + sizeof(struct vr_udp) + sizeof(struct vr_ip) + \
        VR_ETHER_HLEN)


struct vr_mirror_entry {
    unsigned int mir_rid;
    int mir_vni;
    unsigned int mir_flags;
    struct vr_nexthop *mir_nh;
};

struct vr_mirror_meta_entry {
    struct vrouter *mirror_router;
    void *mirror_md;
    unsigned int mirror_md_len;
    unsigned int mirror_sip;
    unsigned int mirror_sport;
    unsigned short mirror_vrf;
};

struct vr_forwarding_md;

extern int vr_mirror_init(struct vrouter *);
extern void vr_mirror_exit(struct vrouter *, bool);
extern int vr_mirror(struct vrouter *, uint8_t, struct vr_packet *,
        struct vr_forwarding_md *, mirror_type_t);
extern struct vr_mirror_entry *vrouter_get_mirror(unsigned int, unsigned int);
extern int vrouter_put_mirror(struct vrouter *, unsigned int);
extern struct vr_mirror_meta_entry *
        vr_mirror_meta_entry_set(struct vrouter *, unsigned int,
                    unsigned int, unsigned short,
                    void *, unsigned int,
                    unsigned short);
extern void vr_mirror_meta_entry_del(struct vrouter *,
                                struct vr_mirror_meta_entry *);

#endif /* __VR_MIRROR_H__ */
