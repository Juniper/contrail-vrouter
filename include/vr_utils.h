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
    char if_name[16];
    char if_kind[16];
    char if_mac[6];
    unsigned int if_index;
    unsigned int if_type;
    unsigned int vn_if_index;
    unsigned int if_flags;
};

struct vr_util_flags {
    unsigned int vuf_flag;
    char *vuf_flag_symbol;
    char *vuf_flag_string;
};

#ifdef __cplusplus
}
#endif
#endif /* __VR_UTILS_H__ */
