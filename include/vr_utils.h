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

#include "vr_os.h"
#include <net/if.h> /* For IFNAMSIZ */

struct vn_if {
    char if_name[IFNAMSIZ];
    char if_kind[IFNAMSIZ];
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

#define NUM_TC              8
#define NUM_PG              8
#define NUM_PRIO            8

struct priority {
    uint8_t prio_to_tc[NUM_PRIO];
    uint8_t prio_group_bw[NUM_PG];
    uint8_t tc_to_group[NUM_TC];
    uint8_t tc_bw_pct[NUM_TC];
    uint8_t tc_strictness;
};

#ifdef __cplusplus
}
#endif
#endif /* __VR_UTILS_H__ */
