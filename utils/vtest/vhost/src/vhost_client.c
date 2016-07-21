/*
 * vhost_client.c
 *
 * Vhost data structures procedures. Procedures init/deinit Vhost_Client structures
 *  and handle data.
 *
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
 */


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/un.h>

#include "util.h"
#include "vhost_client.h"
#include "client.h"
#include "sh_mem.h"
#include "virt_queue.h"
#include "vhost_net.h"
#include "virtio_hdr.h"

static int vhost_client_delete_Vhost_Client(Vhost_Client *vhost_client);
static int vhost_client_init_Vhost_Client(Vhost_Client *vhost_client);
static int vhost_client_run_vhost_client(Vhost_Client **vhost_cl, const char *);
static Vhost_Client* vhost_client_create_vhost_client(void);
static int vhost_client_init_control_communication(Vhost_Client *vhost_client);
static int vhost_client_set_mem_Vhost_Client(Vhost_Client *vhost_client);
static int vhost_client_vhost_init_control_msgs(Vhost_Client *vhost_client);


static int
vhost_client_alloc_Vhost_Client(Vhost_Client **vhost_client) {

    if (!vhost_client) {
        fprintf(stderr, "%s(): Error allocating vhost client: no vhost client\n",
            __func__);
        return E_VHOST_CLIENT_ERR_FARG;
    }


    *vhost_client = (Vhost_Client *) calloc(1, sizeof(Vhost_Client));
     if(!*vhost_client) {
        fprintf(stderr, "%s(): Error allocating vhost client: %s (%d)\n",
            __func__, strerror(errno), errno);
         return  E_VHOST_CLIENT_ERR_ALLOC;
     }

     for (size_t i = 0; i < VHOST_CLIENT_VRING_MAX_VRINGS; i++) {
         (*vhost_client)->virtq_control[i] = calloc(1, sizeof(virtq_control));
         if ((*vhost_client)->virtq_control[i] == NULL) {
            fprintf(stderr, "%s(): Error allocating control queue: %s (%d)\n",
                __func__, strerror(errno), errno);
            return E_VHOST_CLIENT_ERR_ALLOC;
         }
     }

     return E_VHOST_CLIENT_OK;
}

static int
vhost_client_dealloc_Vhost_Client(Vhost_Client *vhost_client) {

    for (size_t i = 0 ; i < VHOST_CLIENT_VRING_MAX_VRINGS; i++) {
        vhost_client_safe_free(vhost_client->virtq_control[i]);
    }
    vhost_client_safe_free(vhost_client);

    return E_VHOST_CLIENT_OK;

}

static int
vhost_client_init_Vhost_Client(Vhost_Client *vhost_client) {

    Vhost_Client *const vhost_cl = vhost_client;

    if (!vhost_client) {
        fprintf(stderr, "%s(): Error initializing vhost client: no vhost client\n",
            __func__);
        return E_VHOST_CLIENT_ERR_FARG;
    }

    vhost_cl->mem.nregions = VHOST_CLIENT_VRING_MAX_VRINGS;
    vhost_cl->virtq_num = VHOST_CLIENT_VRING_MAX_VRINGS;
    vhost_cl->page_size = VHOST_CLIENT_PAGE_SIZE;

    return E_VHOST_CLIENT_OK;
}

static int inline
vhost_client_set_mem_Vhost_Client(Vhost_Client *vhost_client) {

    int ret = 0;
    void *sh_mem_addr = NULL;
    char fd_path_buff[UNIX_PATH_MAX] = {'\0'};
    Vhost_Client *const vhost_cl = vhost_client;
    VIRT_QUEUE_H_RET_VAL ret_val = E_VIRT_QUEUE_OK;

    if (!vhost_client) {
        fprintf(stderr, "%s(): Error setting vhost client memory: no vhost client\n",
            __func__);
        return E_VHOST_CLIENT_ERR_FARG;
    }

    for (size_t i = 0; i < vhost_cl->mem.nregions; i++) {

        snprintf(fd_path_buff, UNIX_PATH_MAX, "%s.%d.shmem",
            vhost_cl->client.sh_mem_path, (int)i);

        ret = sh_mem_init_fd(fd_path_buff,
                (vhost_cl->client.sh_mem_fds + i));
        if (ret != E_SH_MEM_OK) {
            return E_VHOST_CLIENT_ERR_UNK;
        }

        sh_mem_addr = sh_mem_mmap(*(vhost_cl->client.sh_mem_fds + i),
                vhost_cl->page_size);
        if (sh_mem_addr == NULL ) {
            return E_VHOST_CLIENT_ERR_UNK;
        }

        vhost_cl->mem.regions[i].userspace_addr = (uintptr_t) sh_mem_addr;
        vhost_cl->mem.regions[i].guest_phys_addr = (uintptr_t) sh_mem_addr;
        vhost_cl->mem.regions[i].memory_size = vhost_cl->page_size;
        vhost_cl->mem.regions[i].mmap_offset = 0;

        memset(fd_path_buff, 0, sizeof(fd_path_buff));
    }

    ret_val = virt_queue_map_all_mem_reqion_virtq(vhost_cl->sh_mem_virtq_table,
           &vhost_client->mem, VHOST_CLIENT_VRING_MAX_VRINGS);
    if (ret_val != E_VIRT_QUEUE_OK) {
        return ret_val;
    }
    return E_VHOST_CLIENT_OK;
}

static Vhost_Client*
vhost_client_create_vhost_client(void) {

    Vhost_Client *vhost_client = NULL;
    VHOST_CLIENT_H_RET_VAL vhost_client_ret_val = E_VHOST_CLIENT_OK;

    vhost_client_ret_val = vhost_client_alloc_Vhost_Client(&vhost_client);
    if (vhost_client_ret_val != E_VHOST_CLIENT_OK) {
        return NULL;
    }

    vhost_client_ret_val = vhost_client_init_Vhost_Client(vhost_client);
    if (vhost_client_ret_val != E_VHOST_CLIENT_OK) {
        return NULL;
    }

    return vhost_client;
}


static int
vhost_client_unset_sh_mem_Vhost_Client(Vhost_Client *vhost_client) {

    char fd_path_buff[UNIX_PATH_MAX] = {'\0'};
    Vhost_Client *const vhost_cl = vhost_client;

    if (!vhost_client) {
        return E_VHOST_CLIENT_ERR_FARG;
    }

    for (size_t i = 0; i < vhost_client->mem.nregions; i++) {
        snprintf(fd_path_buff, UNIX_PATH_MAX, "%s.%d.shmem", vhost_cl->client.sh_mem_path, (int)i);

        sh_mem_unmmap((void *)vhost_cl->mem.regions[i].guest_phys_addr,
                vhost_cl->mem.regions[i].memory_size);
        sh_mem_unlink(fd_path_buff);

        memset(fd_path_buff, 0, sizeof(fd_path_buff));
    }

    return E_VHOST_CLIENT_OK;
}

static int
vhost_client_delete_Vhost_Client(Vhost_Client *vhost_client) {

    VHOST_CLIENT_H_RET_VAL vhost_client_ret_val = E_VHOST_CLIENT_OK;

    Vhost_Client *const vhost_cl = vhost_client;

    if (!vhost_client) {
        return E_VHOST_CLIENT_ERR_FARG;
    }

    client_disconnect_socket(&vhost_cl->client);
    client_close_fds(&vhost_cl->client);

    vhost_client_unset_sh_mem_Vhost_Client(vhost_cl);
    vhost_client_ret_val = vhost_client_dealloc_Vhost_Client(vhost_cl);


    return vhost_client_ret_val;
}

static int
vhost_client_run_vhost_client(Vhost_Client **vhost_cl, const char *vhost_client_path ) {

    Vhost_Client *l_vhost_client = NULL;
    VHOST_CLIENT_H_RET_VAL vhost_client_ret_val = E_VHOST_CLIENT_OK;
    CLIENT_H_RET_VAL client_ret_val = E_CLIENT_OK;
    VIRT_QUEUE_H_RET_VAL virt_queue_ret_val = E_VIRT_QUEUE_OK;

    if (!vhost_cl || !strlen(vhost_client_path)) {
        fprintf(stderr, "%s(): Error running vhost client: no vhost client\n",
            __func__);
        return E_VHOST_CLIENT_ERR_FARG;
    }

    l_vhost_client = vhost_client_create_vhost_client();
    *vhost_cl = l_vhost_client;
    if (!l_vhost_client) {
        return E_VHOST_CLIENT_ERR;
    }

    client_ret_val = client_init_Client(&l_vhost_client->client, vhost_client_path);
    if (client_ret_val != E_CLIENT_OK) {
        return E_VHOST_CLIENT_ERR;
    }
    vhost_client_ret_val = vhost_client_set_mem_Vhost_Client(l_vhost_client);
    if (vhost_client_ret_val != E_VHOST_CLIENT_OK) {
        return E_VHOST_CLIENT_ERR_SET_SH_MEM;
    }

    vhost_client_ret_val = vhost_client_init_control_communication(l_vhost_client);
    if (vhost_client_ret_val != E_VHOST_CLIENT_OK) {
        fprintf(stderr, "%s(): Error running vhost client: error initializing control communication\n",
            __func__);
        return E_VHOST_CLIENT_ERR_INIT_COMMUNICATION;
    }

    virt_queue_ret_val = virt_queue_map_uvhost_virtq_2_virtq_control(l_vhost_client);
    if (virt_queue_ret_val != E_VIRT_QUEUE_OK) {
        fprintf(stderr, "%s(): Error running vhost client: error mapping queues\n",
            __func__);
        return E_VHOST_CLIENT_ERR_MAP_VIRTQ;
    }


    l_vhost_client->vhost_net_app_handler.context = l_vhost_client;

    l_vhost_client->vhost_net_app_handler.rx_func_handler = vhost_client_poll_client_rx;
    l_vhost_client->vhost_net_app_handler.tx_func_handler = vhost_client_poll_client_tx;
//TODO: Burst
    virt_queue_put_rx_virt_queue(l_vhost_client->virtq_control, VHOST_CLIENT_VRING_IDX_RX , ETH_MAX_MTU);

    return E_VHOST_CLIENT_OK;
}

static int
vhost_client_init_control_communication(Vhost_Client *vhost_client) {

    Vhost_Client *const l_vhost_client = vhost_client;
    VHOST_CLIENT_H_RET_VAL ret_val = E_VHOST_CLIENT_OK;

    if (!vhost_client) {
        return E_VHOST_CLIENT_ERR_FARG;
    }

    ret_val = vhost_client_vhost_init_control_msgs(l_vhost_client);
    if (ret_val != E_VHOST_CLIENT_OK) {
        return ret_val;
    }

    return E_VHOST_CLIENT_OK;
}

static int inline
vhost_client_vhost_init_control_msgs(Vhost_Client *vhost_client) {

    Client *l_client = NULL ;
    Vhost_Client *const l_vhost_client = vhost_client;
    CLIENT_H_RET_VAL client_ret_val = E_CLIENT_OK;
    VIRT_QUEUE_H_RET_VAL virt_queue_ret_val = E_VIRT_QUEUE_OK;

    if (!vhost_client) {
        return E_VHOST_CLIENT_ERR_FARG;
    }

    l_client = &(l_vhost_client)->client;

    if (!l_client->socket || !(strlen(l_client->socket_path))) {
        return E_VHOST_CLIENT_ERR_FARG;
    }

    client_ret_val = client_vhost_ioctl(l_client, VHOST_USER_SET_OWNER, 0);
    if (client_ret_val != E_CLIENT_OK) {
        return E_VHOST_CLIENT_ERR;
    }

    client_ret_val = (client_vhost_ioctl(l_client, VHOST_USER_GET_FEATURES,
               &l_vhost_client->features));
    if (client_ret_val != E_CLIENT_OK) {
        return E_VHOST_CLIENT_ERR;
    }

    client_ret_val = (client_vhost_ioctl(l_client, VHOST_USER_SET_MEM_TABLE,
               &l_vhost_client->mem));
    if (client_ret_val != E_CLIENT_OK) {
        return E_VHOST_CLIENT_ERR;
    }

    virt_queue_ret_val = virt_queue_set_host_virtq_table(l_vhost_client->sh_mem_virtq_table,
                VHOST_CLIENT_VRING_MAX_VRINGS, l_client);

    return virt_queue_ret_val;
}

static vhost_net_state
map_ret_val_vhost_client_2_vhost_net(VHOST_CLIENT_H_RET_VAL vhost_client_ret_val) {

    switch (vhost_client_ret_val) {
        case E_VHOST_CLIENT_OK:
            return E_VHOST_NET_OK;
            break;

        case E_VHOST_CLIENT_ERR_INIT_COMMUNICATION:
            return E_VHOST_NET_ERR_INIT_COMMUNICATION;
            break;

        case E_VHOST_CLIENT_ERR_SET_SH_MEM:
            return E_VHOST_NET_ERR_SET_SH_MEM;
            break;

        case E_VHOST_CLIENT_ERR_MAP_VIRTQ:
            return E_VHOST_NET_ERR_MAP_VIRTQ;
            break;

        default:
            fprintf(stderr, "%s(): Error converting error: unknown error %d\n",
                __func__, vhost_client_ret_val);
            return E_VHOST_NET_ERR_UNK;
            break;
    };

}

int
init_vhost_net(vhost_net **client,  const char *vhost_client_path ) {

    Vhost_Client *run_vhost_client= NULL;
    VHOST_CLIENT_H_RET_VAL vhost_client_ret_val = E_VHOST_CLIENT_OK;

    if (!client || !vhost_client_path || !strlen(vhost_client_path)) {
        fprintf(stderr, "%s(): Error initializing vhost net: no client path\n",
            __func__);
        return E_VHOST_NET_ERR_FARG;
    }


    vhost_client_ret_val = vhost_client_run_vhost_client(&run_vhost_client,
            vhost_client_path);

    if (vhost_client_ret_val != E_VHOST_CLIENT_OK) {
        return map_ret_val_vhost_client_2_vhost_net(vhost_client_ret_val);
    }

    (*client) = calloc(1, sizeof(vhost_net));
    if(!(*client)) {
        fprintf(stderr, "%s(): Error initializing vhost net: %s (%d)\n",
            __func__, strerror(errno), errno);
        return E_VHOST_NET_ERR_ALLOC;
    }

    (*client)->context = run_vhost_client;
    (*client)->tx = run_vhost_client->vhost_net_app_handler.tx_func_handler;
    (*client)->rx = run_vhost_client->vhost_net_app_handler.rx_func_handler;


    return E_VHOST_NET_OK;
}

int
deinit_vhost_net(vhost_net *client) {

    Vhost_Client *deinit_vhost_client = NULL;

    if (!client) {
        return E_VHOST_NET_ERR_FARG;
    }

    deinit_vhost_client = (Vhost_Client *) client->context;
    vhost_client_delete_Vhost_Client(deinit_vhost_client);
    safer_free(((void**)&(client)));

    return E_VHOST_NET_OK;
}



static inline int
send_packet(Vhost_Client *vhost_client, void *src_buf, size_t src_buf_len) {

    VIRT_QUEUE_H_RET_VAL virt_queue_ret_val = E_VIRT_QUEUE_OK;

    virt_queue_ret_val =virt_queue_put_tx_virt_queue(vhost_client->virtq_control,
            VHOST_CLIENT_VRING_IDX_TX, src_buf, src_buf_len);

    return virt_queue_ret_val;
}

static inline int
map_ret_val_virt_queue_2_vhost_net(VIRT_QUEUE_H_RET_VAL virt_queue_ret_val) {

    switch (virt_queue_ret_val) {
        case E_VIRT_QUEUE_OK:
            return E_VHOST_NET_OK;
            break;

        case E_VIRT_QUEUE_ERR_FARG:
            return E_VHOST_NET_ERR_FARG;
            break;

        case E_VIRT_QUEUE_ERR_SEND_PACKET:
        case E_VIRT_QUEUE_ERR_SEND_PACKET_SPACE:
            return E_VHOST_NET_ERR_SEND_PACKET;
            break;

        case E_VIRT_QUEUE_ERR_ALLOC_PACKET:
            return E_VHOST_NET_ERR_ALLOC_PACKET;
            break;

        case E_VIRT_QUEUE_ERR_RECV_PACKET:
        case E_VIRT_QUEUE_ERR_RECV_PACKET_SPACE:
            return E_VHOST_NET_ERR_RECV_PACKET;
            break;

        default:
            return E_VHOST_NET_ERR_UNK;
            break;
    };

}

int
vhost_client_poll_client_tx(void *context, void *src_buf , size_t *src_buf_len) {

    Vhost_Client *vhost_client = NULL;
    VHOST_CLIENT_VRING vq_id = VHOST_CLIENT_VRING_IDX_TX;
    VIRT_QUEUE_H_RET_VAL virt_queue_ret_val = E_VIRT_QUEUE_OK;

    if (!context || !src_buf || src_buf_len == 0) {
        return map_ret_val_virt_queue_2_vhost_net(E_VIRT_QUEUE_ERR_FARG);
    }

    vhost_client = (Vhost_Client *) context;
    virt_queue_ret_val = virt_queue_process_used_tx_virt_queue(vhost_client->virtq_control, vq_id);

    virt_queue_ret_val = send_packet(vhost_client, src_buf, *src_buf_len);
    return map_ret_val_virt_queue_2_vhost_net(virt_queue_ret_val);

}

static inline int
recv_packet(virtq_control *virtq_control, uint64_t *dst_buf, size_t *dst_buf_len) {

    struct virtq_used *used = NULL;
    struct virtq_desc *desc = NULL;
    uint16_t last_used_idx = 0;
    uint64_t num = 0;
    uintptr_t *data_point = NULL;
    size_t data_size = 0;

    if (!virtq_control || !dst_buf ) {
        return E_VHOST_CLIENT_ERR_FARG;
    }
     last_used_idx = virtq_control->last_used_idx;
    used = virtq_control->virtq.used;
    desc = virtq_control->virtq.desc;
    num = virtq_control->virtq.num;

    if (last_used_idx != used->idx) {

        data_point = (uintptr_t *) ((uintptr_t)desc[used->ring[last_used_idx %num].id].addr
                + (uintptr_t)sizeof(struct virtio_net_hdr));
        data_size = used->ring[last_used_idx % num].len - sizeof(struct virtio_net_hdr);

        memcpy((void *)(dst_buf), (void*) data_point, data_size);
        *dst_buf_len = data_size;

    } else {
        return E_VIRT_QUEUE_ERR_RECV_PACKET;
    }
    return E_VIRT_QUEUE_OK;
}

int
vhost_client_poll_client_rx(void *context, void *dst_buf, size_t *dst_buf_len) {

    Vhost_Client *vhost_client = NULL;
    VHOST_CLIENT_VRING vq_id = VHOST_CLIENT_VRING_IDX_RX;
    VIRT_QUEUE_H_RET_VAL virt_queue_ret_val = E_VIRT_QUEUE_OK;

    if (!context || !dst_buf ) {
        return map_ret_val_virt_queue_2_vhost_net(E_VIRT_QUEUE_ERR_FARG);
    }

    vhost_client = (Vhost_Client *) context;

    virt_queue_ret_val = recv_packet((vhost_client->virtq_control[vq_id]),
            (uint64_t *)dst_buf, dst_buf_len);
    if (virt_queue_ret_val == E_VIRT_QUEUE_OK) {
        virt_queue_process_used_rx_virt_queue(vhost_client->virtq_control, vq_id);
        //TODO: Burst
        virt_queue_put_rx_virt_queue(vhost_client->virtq_control,
                vq_id, ETH_MAX_MTU);
    }

    return map_ret_val_virt_queue_2_vhost_net(virt_queue_ret_val);
}

