/*
 * vr_uvhost_msg.h - header for handlers for messages received by the user space
 * vhost thread.
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_UVHOST_MSG_H__
#define __VR_UVHOST_MSG_H__

#include "vr_dpdk_virtio.h"
#include "vr_dpdk.h"
/*
 * Definitions of messages from the netlink thread that are handled by the
 * user space vhost thread
 */

#define VR_UVH_VIF_PFX "uvh_vif_"
#define VHOST_USER_VERSION 1

typedef enum vrnu_msg_type {
    VRNU_MSG_VIF_ADD = 1,
    VRNU_MSG_VIF_DEL,
    VRNU_MSG_MAX
} vrnu_msg_type_t;

typedef enum vrnu_vhostuser_mode_type {
    VRNU_VIF_MODE_CLIENT = 0,
    VRNU_VIF_MODE_SERVER
} vrnu_vhostuser_mode_type_t;

typedef struct vrnu_vif_add {
    char vrnu_vif_name[VR_INTERFACE_NAME_LEN];
    unsigned int vrnu_vif_idx;
    unsigned int vrnu_vif_nrxqs;
    unsigned int vrnu_vif_ntxqs;
    unsigned int vrnu_vif_gen;
    vrnu_vhostuser_mode_type_t vrnu_vif_vhostuser_mode;
} vrnu_vif_add_t;

typedef struct vrnu_vif_del {
    unsigned int vrnu_vif_idx;
} vrnu_vif_del_t;

typedef struct vrnu_msg {
    vrnu_msg_type_t vrnum_type;
    union {
        vrnu_vif_add_t vrnum_vif_add;
        vrnu_vif_del_t vrnum_vif_del;
    };
} vrnu_msg_t;
int vr_uvh_nl_listen_handler(int fd, void *arg);
#endif /* __VR_UVHOST_MSG_H__ */
