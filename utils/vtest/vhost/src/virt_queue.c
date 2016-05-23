/*
 * virt_queue.c
 *
 * Map and handle data rings.
 *
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
 */

#include <string.h>
#include <sys/eventfd.h>
#include <stdio.h>


#include "client.h"
#include "uvhost.h"
#include "vhost_client.h"
#include "virt_queue.h"


int
virt_queue_map_all_mem_reqion_virtq(struct uvhost_virtq **virtq, VhostUserMemory *mem,
                                     size_t virtq_number) {

    VIRT_QUEUE_H_RET_VAL ret_val = E_VIRT_QUEUE_OK;

    if (!virtq) {
        return E_VIRT_QUEUE_ERR_FARG;
    }

    for (size_t i = 0; i < virtq_number; i++) {
        ret_val = (virt_queue_map_mem_reqion_virtq((&(virtq[i])),
                    mem->regions[i].guest_phys_addr));
        if (ret_val != E_VIRT_QUEUE_OK){
            return ret_val;
        }
    }

    return E_VIRT_QUEUE_OK;
}

int
virt_queue_map_mem_reqion_virtq(struct uvhost_virtq **virtq, uint64_t guest_phys_addr) {

    if (!virtq) {
        return E_VIRT_QUEUE_ERR_FARG;
    }

    virt_queue_map_vring(virtq, (void *)guest_phys_addr);
    if (!*virtq) {
        return E_VIRT_QUEUE_ERR_MAP_REG;
    }

    return E_VIRT_QUEUE_OK;
}

int
virt_queue_map_uvhost_virtq_2_virtq_control(Vhost_Client *vhost_client) {

    struct uvhost_virtq **uvhost_virtq = NULL;
    struct virtq_control **virtq_control = NULL;

    if (!vhost_client) {
        return E_VIRT_QUEUE_ERR_FARG;
    }

    uvhost_virtq = vhost_client->sh_mem_virtq_table;
    virtq_control = vhost_client->virtq_control;

    if (!uvhost_virtq) {
        return E_VIRT_QUEUE_ERR_FARG;
    }

    for (size_t vq_id = 0; vq_id < VHOST_CLIENT_VRING_MAX_VRINGS; vq_id++) {

        virtq_control[vq_id]->last_used_idx = 0;
        virtq_control[vq_id]->kickfd = uvhost_virtq[vq_id]->kickfd;
        virtq_control[vq_id]->callfd = uvhost_virtq[vq_id]->callfd;
        virtq_control[vq_id]->virtq.desc = uvhost_virtq[vq_id]->desc;
        virtq_control[vq_id]->virtq.avail = &uvhost_virtq[vq_id]->avail;
        virtq_control[vq_id]->virtq.used = &uvhost_virtq[vq_id]->used;
        virtq_control[vq_id]->virtq.num = VIRTQ_DESC_MAX_SIZE;

    }

    return E_VIRT_QUEUE_OK;
}

int
virt_queue_map_vring(struct uvhost_virtq **virtq, void *base_virtq_addr) {

    struct uvhost_virtq *virtq_map = (struct uvhost_virtq *)base_virtq_addr;
    uintptr_t desc_addr = (uintptr_t)((uintptr_t)virtq_map + sizeof(struct uvhost_virtq));

    if (!virtq || !base_virtq_addr) {

        return E_VIRT_QUEUE_ERR_FARG;
    }

    for (size_t i = 0; i < VIRTQ_DESC_MAX_SIZE; i++) {

       desc_addr = ALIGN(desc_addr, 8);
       virtq_map->desc[i].len = VIRTQ_DESC_BUFF_SIZE;
       virtq_map->desc[i].flags = VIRTIO_DESC_F_WRITE;
       virtq_map->desc[i].next = i + 1;
       virtq_map->desc[i].addr = desc_addr;

       desc_addr = desc_addr + VIRTQ_DESC_BUFF_SIZE;
    }

    virtq_map->avail.idx = 0;
    virtq_map->used.idx = 0;
    virtq_map->desc[VIRTQ_DESC_MAX_SIZE - 1].next = VIRTQ_IDX_NONE;

    *virtq = virtq_map;

    return E_VIRT_QUEUE_OK;
}

int
virt_queue_set_host_virtq(Client *client, struct set_host_virtq set_virtq) {

    if (!client) {
        return E_VIRT_QUEUE_ERR_FARG;
    }

    if (client_vhost_ioctl(client, VHOST_USER_SET_VRING_NUM, &(set_virtq.num)) != E_CLIENT_OK) {
        return E_VIRT_QUEUE_ERR_HOST_VIRTQ;
    }

    if (client_vhost_ioctl(client, VHOST_USER_SET_VRING_BASE, &(set_virtq.base)) != E_CLIENT_OK) {
        return E_VIRT_QUEUE_ERR_HOST_VIRTQ;
    }

    if (client_vhost_ioctl(client, VHOST_USER_SET_VRING_CALL, &(set_virtq.call)) != E_CLIENT_OK) {
        return E_VIRT_QUEUE_ERR_HOST_VIRTQ;
    }

    if (client_vhost_ioctl(client, VHOST_USER_SET_VRING_ADDR, &(set_virtq.addr)) != E_CLIENT_OK) {
        return E_VIRT_QUEUE_ERR_HOST_VIRTQ;
    }

    if (client_vhost_ioctl(client, VHOST_USER_SET_VRING_KICK, &(set_virtq.kick)) != E_CLIENT_OK) {
        return E_VIRT_QUEUE_ERR_HOST_VIRTQ;
    }

    return E_VIRT_QUEUE_OK;
}

int
virt_queue_set_host_virtq_table(struct uvhost_virtq **virtq, size_t virtq_table_size, Client *client) {

    VIRT_QUEUE_H_RET_VAL ret_val = E_VIRT_QUEUE_OK;
    struct set_host_virtq set_virtq_init;

    if (!virtq || !client) {

        return E_VIRT_QUEUE_ERR_FARG;
    }

    memset(&(set_virtq_init), 0, sizeof(struct set_host_virtq));

    for (size_t i = 0; i < virtq_table_size; i++) {

        virtq[i]->kickfd = eventfd(0, EFD_NONBLOCK);
        virtq[i]->callfd = eventfd(0, EFD_NONBLOCK);

        set_virtq_init.num.index = i;
        set_virtq_init.num.num = VIRTQ_DESC_MAX_SIZE;

        set_virtq_init.base.index = i;
        set_virtq_init.base.num = 0;

        set_virtq_init.kick.index = i;
        set_virtq_init.kick.fd = virtq[i]->kickfd;

        set_virtq_init.call.index = i;
        set_virtq_init.call.fd = virtq[i]->callfd;

        if (set_virtq_init.kick.fd < 0 || set_virtq_init.kick.fd < 0) {
            return E_VIRT_QUEUE_ERR_HOST_VIRTQ;
        }

       set_virtq_init.addr.index = i;
       set_virtq_init.addr.desc_user_addr = (uintptr_t)&virtq[i]->desc;
       set_virtq_init.addr.avail_user_addr = (uintptr_t)&virtq[i]->avail;
       set_virtq_init.addr.used_user_addr = (uintptr_t)&virtq[i]->used;
       set_virtq_init.addr.log_guest_addr = (uintptr_t)NULL;
       set_virtq_init.addr.flags = 0;

       ret_val = virt_queue_set_host_virtq(client, set_virtq_init);
       if (ret_val != E_VIRT_QUEUE_OK) {
            return ret_val;
       }
       memset(&(set_virtq_init), 0, sizeof(struct set_host_virtq));

    }

    return E_VIRT_QUEUE_OK;
}

static inline void
init_desc_element(size_t desc_len, struct virtq_desc *desc_id) {

    desc_id->len = desc_len;
    desc_id->flags = VIRTIO_DESC_F_WRITE;
    desc_id->next = VIRTQ_IDX_NONE;

    return;
}

static inline void
init_virtio_hdr(void *mem) {

    struct virtio_net_hdr *virtio_hdr = (struct virtio_net_hdr *)mem;

    virtio_hdr->csum_start =0;
    virtio_hdr->csum_offset = 0;
    virtio_hdr->flags = VRING_AVAIL_F_NO_INTERRUPT;
    virtio_hdr->gso_type = 0;
    virtio_hdr->gso_size = 0;
    virtio_hdr->hdr_len = 0;

    return;
}

/*Copy data from src_buf to desc,
 * currently only single buffer is supported
 *      => src_buf_len MUST NOT be greater than desc[x].len
 */
int
virt_queue_put_tx_virt_queue(struct virtq_control **virtq_control, VHOST_CLIENT_VRING vq_id,
        void *src_buf, size_t src_buf_len) {

    struct virtq_avail* avail = NULL;
    struct virtq_desc* desc = NULL;
    struct virtq_used *used = NULL;

    size_t num = 0;
    uint16_t last_avail_idx = 0;
    uint16_t last_used_idx = 0;
    void *desc_address = NULL;

    if (!virtq_control) {
        return E_VIRT_QUEUE_ERR_FARG;
    }

    used = virtq_control[vq_id]->virtq.used;
    avail = virtq_control[vq_id]->virtq.avail;
    desc = virtq_control[vq_id]->virtq.desc;
    num = virtq_control[vq_id]->virtq.num;
    last_avail_idx = avail->ring[avail->idx %num];
    last_used_idx = virtq_control[vq_id]->last_used_idx;

    if (src_buf_len + sizeof(struct virtio_net_hdr) > desc[last_avail_idx].len) {
        return E_VIRT_QUEUE_ERR_FARG;
    }

    if ( avail->idx % num < last_used_idx % num && last_used_idx %num  - (avail->idx % num ) <= 1) {
        return E_VIRT_QUEUE_ERR_SEND_PACKET_SPACE;
    } else if ( last_used_idx % num < avail->idx % num  && avail->idx % num  - last_used_idx % num> num -1 ) {
        return E_VIRT_QUEUE_ERR_SEND_PACKET_SPACE;
    } else if (last_used_idx != used->idx  && avail->idx %num  == last_used_idx %num) {
        return E_VIRT_QUEUE_ERR_SEND_PACKET_SPACE;
    }
    desc_address = (void *)(uintptr_t) desc[last_avail_idx].addr;
    init_virtio_hdr(desc_address);

    memcpy((void *) ((uintptr_t)desc_address + (uintptr_t)sizeof(struct virtio_net_hdr)),
            src_buf, src_buf_len);

    init_desc_element(sizeof(struct virtio_net_hdr) + src_buf_len, &desc[last_avail_idx]);

    avail->ring[avail->idx % num] = last_avail_idx;
    avail->idx++;


    return E_VIRT_QUEUE_OK;
}

int
virt_queue_put_rx_virt_queue(struct virtq_control **virtq_control, VHOST_CLIENT_VRING vq_id,
        size_t src_buf_len) {

    struct virtq_avail* avail = NULL;
    struct virtq_desc* desc = NULL;
    struct virtq_used *used = NULL;

    size_t num = 0;
    uint16_t last_avail_idx = 0;
    uint16_t last_used_idx = 0;

    if (!virtq_control) {
        return E_VIRT_QUEUE_ERR_FARG;
    }

    used = virtq_control[vq_id]->virtq.used;
    avail = virtq_control[vq_id]->virtq.avail;
    desc = virtq_control[vq_id]->virtq.desc;
    num = virtq_control[vq_id]->virtq.num;
    last_avail_idx = avail->ring[avail->idx % num];
    last_used_idx = virtq_control[vq_id]->last_used_idx;

    if (src_buf_len > desc[last_avail_idx].len) {
        return E_VIRT_QUEUE_ERR_FARG;
    }
    if ( avail->idx % num < last_used_idx % num && last_used_idx %num  - (avail->idx % num ) <= 1) {
        return E_VIRT_QUEUE_ERR_RECV_PACKET_SPACE;
    } else if ( ((last_used_idx % num ) < (avail->idx % num))  && ((avail->idx % num)  - (last_used_idx % num) > (num -1))) {
        return E_VIRT_QUEUE_ERR_RECV_PACKET_SPACE;
    } else if (last_used_idx != used->idx  && avail->idx %num  == last_used_idx %num) {
        return E_VIRT_QUEUE_ERR_RECV_PACKET_SPACE;
    }

    init_desc_element(sizeof(struct virtio_net_hdr) + src_buf_len, &desc[last_avail_idx]);

    avail->ring[avail->idx % num] = last_avail_idx;
    avail->idx++;

    return E_VIRT_QUEUE_OK;
}


int
virt_queue_process_used_tx_virt_queue(struct virtq_control **virtq_control,
        VHOST_CLIENT_VRING vq_id) {

    struct virtq_used* used = NULL;
    uint16_t last_used_idx = 0;
    unsigned int num = 0;

    if (!virtq_control) {
        return E_VIRT_QUEUE_ERR_FARG;
    }

    num = virtq_control[vq_id]->virtq.num;
    used = virtq_control[vq_id]->virtq.used;
    last_used_idx = virtq_control[vq_id]->last_used_idx;

    for (;last_used_idx != used->idx; last_used_idx++ ) {
        virt_queue_free_virt_queue(virtq_control, vq_id, used->ring[last_used_idx % num].id);
    }

    virtq_control[vq_id]->last_used_idx = last_used_idx;

    return E_VIRT_QUEUE_OK;
}

int
virt_queue_process_used_rx_virt_queue(struct virtq_control **virtq_control,
        VHOST_CLIENT_VRING vq_id) {

    struct virtq_used* used = NULL;
    uint16_t last_used_idx = 0;
    unsigned int num = 0;

    if (!virtq_control) {
        return E_VIRT_QUEUE_ERR_FARG;
    }

    num = virtq_control[vq_id]->virtq.num;
    used = virtq_control[vq_id]->virtq.used;
    last_used_idx = virtq_control[vq_id]->last_used_idx;

    if (last_used_idx != used->idx)  {
        virt_queue_free_virt_queue(virtq_control, vq_id, used->ring[last_used_idx % num].id);
        last_used_idx++;
    }

    virtq_control[vq_id]->last_used_idx = last_used_idx;

    return E_VIRT_QUEUE_OK;
}

int
virt_queue_free_virt_queue(struct virtq_control **virtq_control, VHOST_CLIENT_VRING vq_id, uint32_t desc_idx) {

    struct virtq_desc* desc = NULL;
    uint16_t free_idx = 0;

    if (!virtq_control) {
        return E_VIRT_QUEUE_ERR_FARG;
    }

    desc = virtq_control[vq_id]->virtq.desc;
    free_idx = virtq_control[vq_id]->virtq.avail->ring[virtq_control[vq_id]->virtq.avail->idx];;

    desc[desc_idx].len = VIRTQ_DESC_BUFF_SIZE;
    desc[desc_idx].flags |= VIRTIO_DESC_F_WRITE | VRING_AVAIL_F_NO_INTERRUPT;
    desc[desc_idx].next = free_idx;

    return E_VIRT_QUEUE_OK;
}


