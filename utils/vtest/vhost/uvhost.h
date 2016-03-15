/*
 * uvhost.h - header for structure and message definitions copied from
 * qemu 2.1.
 *
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
 */

#ifndef QEMU_UVHOST_H
#define QEMU_UVHOST_H

/* TODO: We can import structures from linux/vhost */

#include <stdlib.h>
#include <linux/vhost.h>
#include <stdint.h>

#include "util.h"


#define VHOST_USER_HDR_SIZE (sizeof(struct virtio_net_hdr))
#define VHOST_MEMORY_MAX_NREGIONS    8
typedef enum {
    VHOST_CLIENT_VRING_IDX_RX = 0,
    VHOST_CLIENT_VRING_IDX_TX = 1,
    VHOST_CLIENT_VRING_MAX_VRINGS
}VHOST_CLIENT_VRING;


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

typedef struct Vhost_Client {
    VhostUserMemory mem;
    size_t page_size;
    size_t virtq_num;
    /* Map RX/TX virtq */
    struct uvhost_virtq *sh_mem_virtq_table[VHOST_CLIENT_VRING_MAX_VRINGS];
    struct virtq_control *virtq_control[VHOST_CLIENT_VRING_MAX_VRINGS];
    uint16_t features;
    Client client;
} Vhost_Client;

typedef struct VhostUserMsg {
    VhostUserRequest request;

#define VHOST_USER_VERSION_MASK   (0x3)
#define VHOST_USER_REPLY_MASK     (0x1<<2)
    uint32_t flags;
    uint32_t size; /* the following payload size */
    union {
#define VHOST_USER_VRING_IDX_MASK  (0xff)
#define VHOST_USER_VRING_NOFD_MASK (0x1<<8)
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

typedef enum {
    E_UVHOST_OK = EXIT_SUCCESS,
    E_UVHOST_ERR_ALLOC,
    E_UVHOST_ERR_UNK,
    E_UVHOST_ERR_FARG,
    E_UVHOST_ERR,
    E_UVHOST_LAST
} UVHOST_H_RET_VAL;


#define uvhost_safe_free(ptr) uvhost_safer_free((void**)&(ptr))
static void
uvhost_safer_free(void **mem) {

    if (mem && *mem) {
        free(*mem);
        *mem = NULL;
    }

    return;
}

int uvhost_poll_client_tx(void *context, void *src_buf , size_t *src_buf_len);
int uvhost_poll_client_rx(void *context, void *src_buf , size_t *src_buf_len);

int uvhost_kick_client(struct fd_rw_element *fd_rw_element);
int uvhost_delete_Vhost_Client(Vhost_Client *vhost_client);
static int uvhost_init_Vhost_Client(Vhost_Client *vhost_client);
int uvhost_run_vhost_client(Vhost_Client **vhost_cl, const char *, CLIENT_TYPE);
static Vhost_Client* uvhost_create_vhost_client(void);
int uvhost_init_control_communication(Vhost_Client *vhost_client);
static int uvhost_set_mem_Vhost_Client(Vhost_Client *vhost_client);
static int uvhost_vhost_init_control_msgs(Vhost_Client *vhost_client);
int uvhost_init_control_communication(Vhost_Client *vhost_client);

#endif
