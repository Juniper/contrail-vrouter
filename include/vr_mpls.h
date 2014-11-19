/*
 * vr_mpls.h --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_MPLS_H__
#define __VR_MPLS_H__

#define VR_MPLS_LABEL_SHIFT         12
#define VR_MPLS_HDR_LEN             4
#define VR_MAX_UCAST_LABELS         1024
#define VR_MAX_LABELS               5120
#define VR_MPLS_STACK_BIT           (0x1 << 8)

#define VR_MPLS_OVER_UDP_DST_PORT   51234
#define VR_MPLS_OVER_UDP_SRC_PORT   51000
#define VR_MUDP_PORT_RANGE_START    49152
#define VR_MUDP_PORT_RANGE_END      65535

#define VR_VXLAN_UDP_DST_PORT        4789
#define VR_VXLAN_UDP_SRC_PORT       52000

struct vrouter;
struct vr_packet;
struct vr_forwarding_md;

extern int vr_mpls_init(struct vrouter *);
extern void vr_mpls_exit(struct vrouter *, bool);
extern int vr_mpls_dump(vr_mpls_req *);
extern int vr_mpls_get(vr_mpls_req *);
extern int vr_mpls_add(vr_mpls_req *);
extern int vr_mpls_tunnel_type(unsigned int , unsigned int, unsigned short *);
extern struct vr_nexthop *__vrouter_get_label(struct vrouter *, unsigned int);
extern int vr_mpls_input(struct vrouter *, struct vr_packet *,
                        struct vr_forwarding_md *);



static inline bool 
vr_mpls_is_label_mcast(unsigned int lbl)
{
    if (lbl < VR_MAX_UCAST_LABELS) {
        return false;
    }

    return true;
}

#endif /* __VR_MPLS_H__ */
