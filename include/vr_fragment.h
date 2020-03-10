/*
 * vr_fragment.h --
 *
 * Copyright (c) 2013, Juniper Networks Private Limited,
 * All rights reserved
 */
#ifndef __VR_FRAGMENT_H__
#define __VR_FRAGMENT_H__

#include "vr_os.h"

/* Number of buckets in assembler_table[][] */
#define VR_ASSEMBLER_BUCKET_COUNT               1024
/* Number of fragments per assembler bucket */
#define VR_MAX_FRAGMENTS_PER_ASSEMBLER_QUEUE    256
/* Number of fragments per CPU queue */
#define VR_MAX_FRAGMENTS_PER_CPU_QUEUE          256
/* Number of enqueue attempts to assembler_table */
#define VR_FRAG_ENQUEUE_ATTEMPTS                3
/* Assembler timeout for fragment entries */
#define VR_ASSEMBLER_TIMEOUT_SECS               2
/* Fragment hash table timeout */
#define VR_FRAG_HASH_TABLE_TIMEOUT_SECS         2
/* Fragment hash table scanner interval */
#define VR_FRAG_HASH_TABLE_SCANNER_INTERVAL_MSEC 250
/* Number of entries to scan every time */
#define VR_FRAG_HASH_TABLE_ENTRIES_PER_SCAN     2048
/* Size of fragment hash table */
#define VR_FRAG_HASH_TABLE_ENTRIES              8192
/* Buckets per entry in fragment hash table */
#define VR_FRAG_HASH_TABLE_BUCKETS              4
/* Overflow entries of fragment hash table */
#define VR_FRAG_HASH_OTABLE_ENTRIES             1024

__attribute__packed__open__
struct vr_fragment_key {
    uint64_t fk_sip_u;
    uint64_t fk_sip_l;
    uint64_t fk_dip_u;
    uint64_t fk_dip_l;
    uint32_t fk_id;
    unsigned short fk_vrf;
    /* Custom data */
    unsigned short fk_custom;
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
    /* does frag entry contain valid port */
    bool f_port_info_valid;
} __attribute__packed__close__;

#define f_sip_u f_key.fk_sip_u
#define f_sip_l f_key.fk_sip_l
#define f_dip_u f_key.fk_dip_u
#define f_dip_l f_key.fk_dip_l
#define f_id  f_key.fk_id
#define f_vrf f_key.fk_vrf
#define f_custom f_key.fk_custom
#define f_len f_key.fk_len

int vr_fragment_table_init(struct vrouter *);
void vr_fragment_table_exit(struct vrouter *);
struct vr_fragment *vr_fragment_get(struct vrouter *, unsigned short,
        struct vr_ip *, unsigned short);
int vr_v4_fragment_add(struct vrouter *, unsigned short, struct vr_ip *,
                unsigned short, unsigned short, unsigned short);
int vr_v6_fragment_add(struct vrouter *, unsigned short, struct vr_ip6 *,
                unsigned short, unsigned short, unsigned short);
void vr_fragment_del(vr_htable_t, struct vr_fragment *);
uint32_t vr_fragment_get_hash(struct vr_packet_node *);
int vr_fragment_assemble(struct vr_fragment **,
        struct vr_fragment_queue_element *);
void vr_fragment_assemble_queue(struct vr_fragment_queue *);
unsigned int vr_assembler_table_scan(struct vr_fragment **);
int vr_fragment_enqueue(struct vrouter *, struct vr_fragment_queue *,
        struct vr_packet *, struct vr_forwarding_md *);
int vr_assembler_table_scan_init(void (*)(void *));
void vr_assembler_table_scan_exit(void);
void vr_fragment_queue_free(struct vr_fragment_queue *queue);

#endif /* __VR_FRAGMENT_H__ */
