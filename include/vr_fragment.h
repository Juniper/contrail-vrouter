/*
 * vr_fragment.h --
 *
 * Copyright (c) 2013, Juniper Networks Private Limited,
 * All rights reserved
 */
#ifndef __VR_FRAGMENT_H__
#define __VR_FRAGMENT_H__

#include "vr_os.h"

#define VR_ASSEMBLER_TIMEOUT_TIME               5
#define VR_LINUX_ASSEMBLER_BUCKETS              1024
#define VR_MAX_FRAGMENTS_PER_ASSEMBLER_QUEUE    256
#define VR_MAX_FRAGMENTS_PER_CPU_QUEUE          256
#define VR_FRAG_ENQUEUE_ATTEMPTS                3

__attribute__packed__open__
struct vr_fragment_key {
    uint64_t fk_sip_u;
    uint64_t fk_sip_l;
    uint64_t fk_dip_u;
    uint64_t fk_dip_l;
    uint32_t fk_id;
    unsigned short fk_vrf;
} __attribute__packed__close__;

struct vr_fragment_queue_element {
    struct vrouter *fqe_router;
    struct vr_fragment_queue_element *fqe_next;
    struct vr_packet_node fqe_pnode;
};

struct vr_fragment_queue {
    uint64_t vfq_length;
    struct vr_fragment_queue_element *vfq_tail;
};

__attribute__packed__open__
struct vr_fragment {
    vr_hentry_t f_hentry;
    /* packing to make sure that members are aligned */
    uint8_t f_packing[3];
    struct vr_fragment_key f_key;
    unsigned short f_sport;
    unsigned short f_dport;
    struct vr_fragment *f_next;
    struct vr_fragment_queue_element *f_qe;
    uint64_t f_time;
    uint16_t f_expected;
    uint16_t f_received;
    bool f_port_info_valid;
} __attribute__packed__close__;

#define f_sip_u f_key.fk_sip_u
#define f_sip_l f_key.fk_sip_l
#define f_dip_u f_key.fk_dip_u
#define f_dip_l f_key.fk_dip_l
#define f_id  f_key.fk_id
#define f_vrf f_key.fk_vrf
#define f_len f_key.fk_len

int vr_fragment_table_init(struct vrouter *);
void vr_fragment_table_exit(struct vrouter *);
struct vr_fragment *vr_fragment_get(struct vrouter *, unsigned short,
        struct vr_ip *);
int vr_v4_fragment_add(struct vrouter *, unsigned short, struct vr_ip *,
                unsigned short, unsigned short);
int vr_v6_fragment_add(struct vrouter *, unsigned short, struct vr_ip6 *,
                unsigned short, unsigned short);
void vr_fragment_del(vr_htable_t, struct vr_fragment *);
uint32_t vr_fragment_get_hash(struct vr_packet_node *);
int vr_fragment_assembler(struct vr_fragment **,
        struct vr_fragment_queue_element *);
unsigned int vr_assembler_table_scan(struct vr_fragment **);
int vr_fragment_enqueue(struct vrouter *, struct vr_fragment_queue *,
        struct vr_packet *, struct vr_forwarding_md *);
int vr_assembler_table_scan_init(void (*)(void *));
void vr_assembler_table_scan_exit(void);
void vr_fragment_queue_free(struct vr_fragment_queue *queue);

#endif /* __VR_FRAGMENT_H__ */
