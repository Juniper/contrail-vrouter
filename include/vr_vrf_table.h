/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_VRF_TABLE_H__
#define __VR_VRF_TABLE_H__

#include "vr_os.h"

struct vrouter;

#define VRF_FLAG_VALID           0x0001
#define VRF_FLAG_HBF_L_VALID     0x0002
#define VRF_FLAG_HBF_R_VALID     0x0004

struct vr_vrf_table_entry {
    unsigned int rid;
    uint32_t vrf_flags;
    struct vr_interface *hbf_l_vif;
    struct vr_interface *hbf_r_vif;
};

extern int vr_vrf_table_init(struct vrouter *);
extern void vr_vrf_table_exit(struct vrouter *, bool);
struct vr_vrf_table_entry *
vrouter_get_vrf_table(struct vrouter *router, unsigned int index);
#endif /* __VR_VRF_TABLE_H__ */
