/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_LINUX_H__
#define __VR_LINUX_H__

#include "vrouter.h"

static inline struct sk_buff *
vp_os_packet(struct vr_packet *pkt)
{
    return CONTAINER_OF(cb, struct sk_buff, pkt);
}

/* vr_info - Kernel specific Macro functions
 * For vr_info, callback functions are registered in vr_info.h,
 * those callbacks will be expanded below for function declaration and
 * mapping those functions in vr_lh_host.c */

/* Map only kernel specific callback functions */
#undef VR_INFO_HOST_MAP_KERNEL
#define VR_INFO_HOST_MAP_KERNEL(MSG, CB) \
    .hos_vr_##CB = lh_##CB,

#define VR_INFO_HOST_MAP(MSG, CB, PLTFRM) \
    VR_INFO_HOST_MAP_##PLTFRM(MSG, CB)

#define FOREACH_VR_INFO_MAP() \
    VR_INFO_REG(VR_INFO_HOST_MAP)

#define VR_INFO_DECLARATION(MSG, CB, PLTFRM) \
        int lh_##CB(VR_INFO_ARGS);

#define FOREACH_VR_INFO_DECLARATION() \
    VR_INFO_REG(VR_INFO_DECLARATION)


/* Below macro would be expanded for declaring the kernel callback function
 * used for vr_info */
FOREACH_VR_INFO_DECLARATION()

#endif /* __VR_LINUX_H__ */
