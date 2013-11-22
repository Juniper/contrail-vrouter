/*
 * vr_fragment.h --
 *
 * Copyright (c) 2013, Juniper Networks Private Limited,
 * All rights reserved
 */
#ifndef __VR_FRAGMENT_H__
#define __VR_FRAGMENT_H__

struct vr_fragment_key {
    unsigned int fk_sip;
    unsigned int fk_dip;
    unsigned short fk_id;
    unsigned short fk_vrf;
} __attribute__((packed));

struct vr_fragment {
    struct vr_fragment_key f_key;
    unsigned short f_sport;
    unsigned short f_dport;
    uint64_t f_time;
} __attribute__((packed));

#define f_sip f_key.fk_sip
#define f_dip f_key.fk_dip
#define f_id  f_key.fk_id
#define f_vrf f_key.fk_vrf

int vr_fragment_table_init(struct vrouter *);
void vr_fragment_table_exit(struct vrouter *);
struct vr_fragment *vr_fragment_get(struct vrouter *, unsigned short,
        struct vr_ip *);
int vr_fragment_add(struct vrouter *, unsigned short, struct vr_ip *,
                unsigned short, unsigned short);
void vr_fragment_del(struct vr_fragment *);

#endif /* __VR_FRAGMENT_H__ */
