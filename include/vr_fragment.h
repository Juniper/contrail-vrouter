/*
 * vr_fragment.h --
 *
 * Copyright (c) 2013, Juniper Networks Private Limited,
 * All rights reserved
 */
#ifndef __VR_FRAGMENT_H__
#define __VR_FRAGMENT_H__

#define VR_ASSEMBLER_TIMEOUT_TIME               5
#define VR_LINUX_ASSEMBLER_BUCKETS              1024
#define VR_MAX_FRAGMENTS_PER_ASSEMBLER_QUEUE    256
#define VR_MAX_FRAGMENTS_PER_CPU_QUEUE          256
#define VR_FRAG_ENQUEUE_ATTEMPTS                3

struct vr_fragment_key {
    unsigned int fk_sip;
    unsigned int fk_dip;
    unsigned short fk_id;
    unsigned short fk_vrf;
} __attribute__((packed));

struct vr_fragment_queue_element {
    struct vrouter *fqe_router;
    struct vr_fragment_queue_element *fqe_next;
    struct vr_packet_node fqe_pnode;
};

struct vr_fragment_queue {
    uint64_t vfq_length;
    struct vr_fragment_queue_element *vfq_tail;
};

struct vr_fragment {
    struct vr_fragment_key f_key;
    unsigned short f_sport;
    unsigned short f_dport;
    struct vr_fragment *f_next;
    struct vr_fragment_queue_element *f_qe;
    uint64_t f_time;
    uint16_t f_expected;
    uint16_t f_received;
    bool f_port_info_valid;
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
uint32_t vr_fragment_get_hash(unsigned int, struct vr_packet *);
int vr_fragment_assembler(struct vr_fragment **,
        struct vr_fragment_queue_element *);
unsigned int vr_assembler_table_scan(struct vr_fragment **);
int vr_fragment_enqueue(struct vrouter *, struct vr_fragment_queue *,
        struct vr_packet *, struct vr_forwarding_md *);
int vr_assembler_table_scan_init(void (*)(void *));
void vr_assembler_table_scan_exit(void);
void vr_fragment_queue_free(struct vr_fragment_queue *queue);

#endif /* __VR_FRAGMENT_H__ */
