/*
 * qemu_uvhost.h - header for structure and message definitions copied from
 * qemu 2.1.
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

/*
 * License: GPL-2.0+
 * Copyright (c) 2013 Virtual Open Systems Sarl.
 * https://www.qemu.org
 */

#ifndef __QEMU_UVHOST_H__
#define __QEMU_UVHOST_H__

#include <linux/vhost.h>
#include "vr_dpdk_virtio.h"

#define VHOST_MEMORY_MAX_NREGIONS    8
#define VHOST_CLIENT_MAX_VRINGS      (2 * VR_DPDK_VIRTIO_MAX_QUEUES)

typedef enum VhostUserRequest {
    VHOST_USER_NONE = 0,
    VHOST_USER_GET_FEATURES = 1,
    VHOST_USER_SET_FEATURES = 2,
    VHOST_USER_SET_OWNER = 3,
    VHOST_USER_RESET_OWNER = 4,
    VHOST_USER_SET_MEM_TABLE = 5,
    VHOST_USER_SET_LOG_BASE = 6,
    VHOST_USER_SET_LOG_FD = 7,
    VHOST_USER_SET_VRING_NUM = 8,
    VHOST_USER_SET_VRING_ADDR = 9,
    VHOST_USER_SET_VRING_BASE = 10,
    VHOST_USER_GET_VRING_BASE = 11,
    VHOST_USER_SET_VRING_KICK = 12,
    VHOST_USER_SET_VRING_CALL = 13,
    VHOST_USER_SET_VRING_ERR = 14,
    VHOST_USER_GET_PROTOCOL_FEATURES = 15,
    VHOST_USER_SET_PROTOCOL_FEATURES = 16,
    VHOST_USER_GET_QUEUE_NUM = 17,
    VHOST_USER_SET_VRING_ENABLE = 18,
    VHOST_USER_SEND_RARP = 19,
    VHOST_USER_MAX
} VhostUserRequest;

typedef struct VhostUserMemoryRegion {
    uint64_t guest_phys_addr;
    uint64_t memory_size;
    uint64_t userspace_addr;
    uint64_t mmap_offset;
} VhostUserMemoryRegion;

typedef struct VhostUserMemory {
    uint32_t nregions;
    uint32_t padding;
    VhostUserMemoryRegion regions[VHOST_MEMORY_MAX_NREGIONS];
} VhostUserMemory;

typedef struct VhostUserMsg {
    VhostUserRequest request;

#define VHOST_USER_VERSION_MASK     (0x3)
#define VHOST_USER_REPLY_MASK       (0x1<<2)
    uint32_t flags;
    uint32_t size; /* the following payload size */
    union {
#define VHOST_USER_VRING_IDX_MASK   (0xff)
#define VHOST_USER_VRING_NOFD_MASK  (0x1<<8)
        uint64_t u64;
        struct vhost_vring_state state;
        struct vhost_vring_addr addr;
        VhostUserMemory memory;
    };
} __attribute__((packed)) VhostUserMsg;

/*
 * VHOST_USER_HSIZE - size of the header of the user space vhost message. This
 * doesn't include the variable part of the message (union above).
 */
#define VHOST_USER_HSIZE (offsetof(VhostUserMsg, u64))

#define VHOST_USER_F_PROTOCOL_FEATURES	30
#define VHOST_USER_PROTOCOL_F_MQ	0
#define VHOST_USER_PROTOCOL_F_LOG_SHMFD	1

#endif /* __QEMU_UVHOST_H__ */

