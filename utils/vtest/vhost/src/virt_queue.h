/*
 * virt_queue.h - some headers, functions and message definitions are copied from
 * reference file (virtio_ring.h)
 *
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
*/
#ifndef VIRT_QUEUE_H
#define VIRT_QUEUE_H
#include <stdint.h>
#include <stdlib.h>

#include "uvhost.h"
#include "virtio_hdr.h"
#include "client.h"
#include "vhost_client.h"

#define VIRTQ_IDX_NONE ((uint16_t)-1)

/* Maximum is set to value 2^15 due to max value idx in ring */
#define VIRTQ_DESC_MAX_SIZE (32768)

/* Maximal ethernet MTU + sizeof(virtio_net_hdr) */
#define VIRTQ_DESC_BUFF_SIZE (ETH_MAX_MTU + sizeof(struct virtio_net_hdr))
#define ETH_MAX_MTU (10000)


typedef enum virtq_desc_flags {

    /* This marks a buffer as continuing via the next field. */
    VIRTIO_DESC_F_NEXT = 1,

    /* This marks a buffer as write-only (otherwise read-only). */
    VIRTIO_DESC_F_WRITE = 2,

    /* This means the buffer contains a list of buffer descriptors. */
    VIRTIO_DESC_F_INDIRECT = 4

} virtq_desc_flags;


/* Virtqueue descriptors: 16 bytes.
 *  * These can chain together via "next". */
struct virtq_desc {
    /* Address (guest-physical). */
    uint64_t addr;
    /* Length. */
    uint32_t len;
    /* The flags as indicated above. */
    uint16_t flags;
    /* We chain unused descriptors via this, too */
    uint16_t next;
};

struct virtq_avail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[VIRTQ_DESC_MAX_SIZE];
    /* Only if VIRTIO_F_EVENT_IDX: le16 used_event; */
};

/* le32 is used here for ids for padding reasons. */
struct virtq_used_elem {
    /* Index of start of used descriptor chain. */
    uint32_t id;
    /* Total length of the descriptor chain which was written to. */
    uint32_t len;
};

struct virtq_used {
    uint16_t flags;
    uint16_t idx;
    struct virtq_used_elem ring[VIRTQ_DESC_MAX_SIZE];
};

typedef struct uvhost_virtq {
    int kickfd;
    int callfd;
    struct virtq_desc desc[VIRTQ_DESC_MAX_SIZE] __attribute__((aligned(4)));
    struct virtq_avail avail                    __attribute__((aligned(2)));
    struct virtq_used used                      __attribute__((aligned(4096)));
} uvhost_virtq;

struct virtq {
    unsigned int num;
    struct virtq_desc *desc;
    struct virtq_avail *avail;
    struct virtq_used *used;
};

typedef struct virtq_control {
    struct virtq virtq;
    uint16_t last_used_idx;
    int kickfd;
    int callfd;
} virtq_control;

struct set_host_virtq {
    struct vhost_vring_state num;
    struct vhost_vring_state base;
    struct vhost_vring_file kick;
    struct vhost_vring_file call;
    struct vhost_vring_addr addr;
} set_virtq_init;

typedef enum {
    E_VIRT_QUEUE_OK = EXIT_SUCCESS,
    E_VIRT_QUEUE_ERR_ALLOC,
    E_VIRT_QUEUE_ERR_UNK,
    E_VIRT_QUEUE_ERR_FARG,
    E_VIRT_QUEUE_ERR_HOST_VIRTQ,
    E_VIRT_QUEUE_ERR_MAP_REG,
    E_VIRT_QUEUE_ERR_SEND_PACKET,
    E_VIRT_QUEUE_ERR_SEND_PACKET_SPACE,
    E_VIRT_QUEUE_ERR_RECV_PACKET,
    E_VIRT_QUEUE_ERR_RECV_PACKET_SPACE,
    E_VIRT_QUEUE_ERR_ALLOC_PACKET,
    E_VIRT_QUEUE_LAST
} VIRT_QUEUE_H_RET_VAL;

int virt_queue_put_tx_virt_queue(struct virtq_control **virtq_control, VHOST_CLIENT_VRING vq_id, void *src_buf, size_t src_buf_len);
int virt_queue_put_rx_virt_queue(struct virtq_control **virtq_control, VHOST_CLIENT_VRING vq_id, size_t src_buf_len);
int virt_queue_process_used_tx_virt_queue(struct virtq_control **virtq_control, VHOST_CLIENT_VRING vq_id);
int virt_queue_process_used_rx_virt_queue(struct virtq_control **virtq_control, VHOST_CLIENT_VRING vq_id);
int virt_queue_free_virt_queue(struct virtq_control **virtq_control, VHOST_CLIENT_VRING vq_id, uint32_t desc_idx);
int virt_queue_process_desc_virt_queue(struct virtq_control **virtq_control, VHOST_CLIENT_VRING vq_id, uint32_t avail_idx);
int virt_queue_process_avail_virt_queue(struct virtq_control **virtq_control ,VHOST_CLIENT_VRING vq_id);
int virt_queue_map_uvhost_virtq_2_virtq_control(Vhost_Client *vhost_client);

int virt_queue_map_all_mem_reqion_virtq(struct uvhost_virtq **virtq, VhostUserMemory *mem,
                                        size_t virtq_number);
int virt_queue_map_vring(struct uvhost_virtq **virtq, void *base_virtq);
int virt_queue_map_mem_reqion_virtq(struct uvhost_virtq **virtq, uint64_t guest_phys_addr);

int virt_queue_set_host_virtq_table(uvhost_virtq **virtq, size_t virtq_table_size, Client *client);

#endif

