/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_MIRROR_H__
#define __VR_MIRROR_H__

#define VR_MAX_MIRROR_INDICES           255
#define VR_MIRROR_FLAG_MARKED_DELETE    0x1

#define VR_MIRROR_MME 0x1
#define VR_MIRROR_PCAP 0x2

struct vrouter;
struct vr_packet;

struct vr_mirror_entry {
    unsigned int mir_users:20;
    unsigned int mir_flags:12;
    unsigned int mir_rid;
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
        struct vr_forwarding_md *);
extern struct vr_mirror_entry *vrouter_get_mirror(unsigned int, unsigned int);
extern int vrouter_put_mirror(struct vrouter *, unsigned int);
extern int vr_mirror_meta_entry_set(struct vrouter *, unsigned int,
        unsigned int, unsigned short,
        void *, unsigned int,
        unsigned short);
extern void vr_mirror_meta_entry_del(struct vrouter *, unsigned int);

#endif /* __VR_MIRROR_H__ */
