/*
 * vr_utils.h -- definitions and other things that are useful for agent/dp
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_UTILS_H__
#define __VR_UTILS_H__
#ifdef __cplusplus
extern "C" {
#endif
struct vn_if {
    char if_name[IFNAMSIZ];
    char if_kind[IFNAMSIZ];
    char if_mac[6];
    unsigned int if_index;
    unsigned int if_type;
    unsigned int vn_if_index;
    unsigned int if_flags;
};

#ifdef __cplusplus
}
#endif
#endif /* __VR_UTILS_H__ */
