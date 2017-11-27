/*
 * vr_qos.h --
 *
 * Copyright (c) 2016, Juniper Networks, Inc.
 * All rights reserved
 */
#ifndef __VR_QOS_H__
#define __VR_QOS_H__

#include "vr_os.h"

#define VR_DEF_QOS_MAP_ENTRIES      4096
#define VR_DEF_FC_MAP_ENTRIES       256
#define VR_DSCP_QOS_ENTRIES         64
#define VR_MPLS_QOS_ENTRIES         8
#define VR_DOTONEP_QOS_ENTRIES      8
#define VR_QOS_MAP_ENTRY_SIZE       (VR_DSCP_QOS_ENTRIES + \
        VR_MPLS_QOS_ENTRIES + \
        VR_DOTONEP_QOS_ENTRIES)

/*
 * We split the structure this way because flow structure has only
 * 3 bytes of space between hash entry and key. Adding any other
 * fields here should mean change in the location of the entry in
 * the flow structure
 */
__attribute__packed__open__
struct vr_forwarding_class_qos {
    uint8_t     vfcq_dscp;
    uint8_t     vfcq_mpls_qos:3,
                vfcq_dotonep_qos:3,
                vfcq_untrusted:1,
                vfcq_valid:1;
    uint8_t     vfcq_queue_id;
} __attribute__packed__close__;

__attribute__packed__open__
struct vr_forwarding_class {
    uint8_t vfc_id;
    struct vr_forwarding_class_qos vfc_qos;
} __attribute__packed__close__;

/* for easy access */
#define vfc_dscp        vfc_qos.vfcq_dscp
#define vfc_mpls_qos    vfc_qos.vfcq_mpls_qos
#define vfc_dotonep_qos vfc_qos.vfcq_dotonep_qos
#define vfc_queue_id    vfc_qos.vfcq_queue_id
#define vfc_untrusted   vfc_qos.vfcq_untrusted
#define vfc_valid       vfc_qos.vfcq_valid

struct vrouter;
struct vr_forwarding_md;
struct vr_packet;

extern int vr_qos_init(struct vrouter *);
extern void vr_qos_exit(struct vrouter *, bool);
struct vr_forwarding_class_qos *vr_qos_get_forwarding_class(struct vrouter *,
        struct vr_packet *, struct vr_forwarding_md *);
extern unsigned int vr_qos_map_req_get_size(void *);

#endif /* __VR_QOS_H__ */
