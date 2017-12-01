/*
 * vr_vxlan.h -- VXLAN encapsulation handling
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_VXLAN_H__
#define __VR_VXLAN_H__

#include "vr_os.h"

#define VR_VXLAN_VNID_SHIFT             8

struct vrouter;
struct vr_forwarding_md;
struct vr_packet;

extern int vr_vxlan_init(struct vrouter *);
extern void vr_vxlan_exit(struct vrouter *, bool);
extern int vr_vxlan_input(struct vrouter *, struct vr_packet *,
                                    struct vr_forwarding_md *);




#endif
