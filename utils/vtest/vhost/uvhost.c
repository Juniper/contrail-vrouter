/*
 * uvhost.c
 *
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
 */

/*TODO Warning/error msgs */
/*TODO close fds - kick and call */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/un.h>

#include "util.h"
#include "uvhost.h"
#include "client.h"
#include "sh_mem.h"
#include "virt_queue.h"
#include "virtio_hdr.h"

/* TODO */

static int
uvhost_alloc_Vhost_Client(Vhost_Client **vhost_client) {

    if (!vhost_client) {
        return E_UVHOST_ERR_FARG;
    }

    *vhost_client = (Vhost_Client *) calloc(1, sizeof(Vhost_Client));
     if(!*vhost_client) {
         return  E_UVHOST_ERR_ALLOC;
     }

     for (size_t i = 0; i < VHOST_CLIENT_VRING_MAX_VRINGS; i++) {
         (*vhost_client)->virtq_control[i] = calloc(1, sizeof(virtq_control));
         if ((*vhost_client)->virtq_control[i] == NULL) {
            return E_UVHOST_ERR_ALLOC;
         }
     }

     return E_UVHOST_OK;
}

int
uvhost_dealloc_Vhost_Client(Vhost_Client *vhost_client) {

    for (size_t i = 0 ; i < VHOST_CLIENT_VRING_MAX_VRINGS; i++) {
        uvhost_safe_free(vhost_client->virtq_control[i]);
    }
    uvhost_safe_free(vhost_client);

    return E_UVHOST_OK;

}

static int
uvhost_init_Vhost_Client(Vhost_Client *vhost_client) {

    Vhost_Client *const vhost_cl = vhost_client;

    if (!vhost_client) {
        return E_UVHOST_ERR_FARG;
    }

    vhost_cl->mem.nregions = VHOST_CLIENT_VRING_MAX_VRINGS;
    vhost_cl->virtq_num = VHOST_CLIENT_VRING_MAX_VRINGS;
    vhost_cl->page_size = VHOST_CLIENT_PAGE_SIZE;

    return E_UVHOST_OK;
}

static int inline
uvhost_set_mem_Vhost_Client(Vhost_Client *vhost_client) {

    int ret = 0;
    void *sh_mem_addr = NULL;
    char fd_path_buff[UNIX_PATH_MAX] = {'\0'};
    Vhost_Client *const vhost_cl = vhost_client;
    VIRT_QUEUE_H_RET_VAL ret_val = E_VIRT_QUEUE_OK;

    if (!vhost_client) {
        return E_UVHOST_ERR_FARG;
    }

    for (size_t i = 0; i < vhost_cl->mem.nregions; i++) {

        snprintf(fd_path_buff, UNIX_PATH_MAX, "%s.%d", vhost_cl->client.sh_mem_path, (int)i);

        ret = sh_mem_init_fd(fd_path_buff,
                (vhost_cl->client.sh_mem_fds + i));
        if (ret != E_SH_MEM_OK) {
            return E_UVHOST_ERR_UNK;
        }

        sh_mem_addr = sh_mem_mmap(*(vhost_cl->client.sh_mem_fds + i),
                vhost_cl->page_size);
        if (sh_mem_addr == NULL ) {
            return E_UVHOST_ERR_UNK;
        }

        vhost_cl->mem.regions[i].userspace_addr = (uintptr_t) sh_mem_addr;
        vhost_cl->mem.regions[i].guest_phys_addr = (uintptr_t) sh_mem_addr;
        vhost_cl->mem.regions[i].memory_size = vhost_cl->page_size;
        vhost_cl->mem.regions[i].mmap_offset = 0;

        memset(fd_path_buff, 0, sizeof(char) * UNIX_PATH_MAX);
    }

    ret_val = virt_queue_map_all_mem_reqion_virtq(vhost_cl->sh_mem_virtq_table,
           &vhost_client->mem, VHOST_CLIENT_VRING_MAX_VRINGS);
    if (ret_val != E_VIRT_QUEUE_OK) {
        return ret_val;
    }
    return E_UVHOST_OK;
}

static Vhost_Client*
uvhost_create_vhost_client(void) {

    Vhost_Client *vhost_client = NULL;
    UVHOST_H_RET_VAL uvhost_ret_val = E_UVHOST_OK;

    uvhost_ret_val = uvhost_alloc_Vhost_Client(&vhost_client);
    if (uvhost_ret_val != E_UVHOST_OK) {
        return NULL;
    }

    uvhost_ret_val = uvhost_init_Vhost_Client(vhost_client);
    if (uvhost_ret_val != E_UVHOST_OK) {
        return NULL;
    }

    return vhost_client;
}


static int
uvhost_unset_sh_mem_Vhost_Client(Vhost_Client *vhost_client) {

    char fd_path_buff[UNIX_PATH_MAX] = {'\0'};
    Vhost_Client *const vhost_cl = vhost_client;
    SH_MEM_H_RET_VAL ret = E_SH_MEM_OK;

    if (!vhost_client) {
        return E_UVHOST_ERR_FARG;
    }

    for (size_t i = 0; i < vhost_client->mem.nregions; i++) {
        snprintf(fd_path_buff, UNIX_PATH_MAX, "%s.%d", vhost_cl->client.sh_mem_path, (int)i);

        ret = sh_mem_unmmap((void *)vhost_cl->mem.regions[i].guest_phys_addr,
                vhost_cl->mem.regions[i].memory_size);
        ret = sh_mem_unlink(fd_path_buff);

        memset(fd_path_buff, 0, sizeof(char) * UNIX_PATH_MAX);
    }

    return E_UVHOST_OK;
}

int
uvhost_close_kick_call_fds_Vhost_client(Vhost_Client *vhost_client) {

    Vhost_Client *const l_vhost_cl = vhost_client;
    int ret = 0;

    if (!vhost_client) {
        return E_UVHOST_ERR_FARG;
    }

    for (size_t i = 0; i < VHOST_CLIENT_VRING_MAX_VRINGS; i++) {

        if (l_vhost_cl->virtq_control[i]->kickfd >= 0) {
            ret = close(l_vhost_cl->virtq_control[i]->kickfd);
            if (ret) return E_UVHOST_ERR;
        }
        if (l_vhost_cl->virtq_control[i]->callfd >= 0){
            ret = close(l_vhost_cl->virtq_control[i]->callfd);
            if (ret) return E_UVHOST_ERR;

        }
    }
    return E_UVHOST_OK;
}

int
uvhost_delete_Vhost_Client(Vhost_Client *vhost_client) {

    UVHOST_H_RET_VAL uvhost_ret_val = E_UVHOST_OK;
    CLIENT_H_RET_VAL client_ret_val = E_CLIENT_OK;

    Vhost_Client *const vhost_cl = vhost_client;

    if (!vhost_client) {
        return E_UVHOST_ERR_FARG;
    }

    client_ret_val = client_disconnect_socket(&vhost_cl->client);
    client_ret_val = client_close_fds(&vhost_cl->client);

    uvhost_unset_sh_mem_Vhost_Client(vhost_cl);
    uvhost_ret_val = uvhost_dealloc_Vhost_Client(vhost_cl);


    return uvhost_ret_val;
}

int
uvhost_run_vhost_client(Vhost_Client **vhost_cl, const char *uvhost_path, CLIENT_TYPE client_type) {

    Vhost_Client *l_vhost_client = NULL;
    UVHOST_H_RET_VAL uvhost_ret_val = E_UVHOST_OK;
    VIRT_QUEUE_H_RET_VAL virt_queue_ret_val = E_VIRT_QUEUE_OK;
    CLIENT_H_RET_VAL client_ret_val = E_CLIENT_OK;

    if (!vhost_cl || strlen(uvhost_path) == 0) {
        return E_UVHOST_ERR_FARG;
    }

    if (client_type >= CLIENT_TYPE_LAST) {
        return E_UVHOST_ERR_FARG;
    }

    l_vhost_client = uvhost_create_vhost_client();
    *vhost_cl = l_vhost_client;
    if (!l_vhost_client) {
        return E_UVHOST_ERR;
    }


    client_ret_val = client_init_Client(&l_vhost_client->client, uvhost_path);
    if (client_ret_val != E_CLIENT_OK) {
        return E_UVHOST_ERR;;
    }
    uvhost_ret_val = uvhost_set_mem_Vhost_Client(l_vhost_client);
    if (uvhost_ret_val != E_UVHOST_OK) {
        return uvhost_ret_val;
    }

    uvhost_ret_val = uvhost_init_control_communication(l_vhost_client);
    if (uvhost_ret_val != E_UVHOST_OK) {
        return uvhost_ret_val;
    }

    virt_queue_ret_val = virt_queue_map_uvhost_virtq_2_virtq_control(l_vhost_client);
/*
 * Actually We do not need it
 *
    utils_add_fd_to_fd_rw_t(&(l_vhost_client->client.fd_rw_list), FD_TYPE_READ,
            l_vhost_client->sh_mem_virtq_table[VHOST_CLIENT_VRING_IDX_RX]->kickfd,
            (void *)l_vhost_client, uvhost_kick_client);
*/
    l_vhost_client->client.vhost_net_app_handler.context = l_vhost_client;

    if (client_type == CLIENT_TYPE_TX) {
        l_vhost_client->client.vhost_net_app_handler.poll_func_handler= uvhost_poll_client_tx;
    } else if (client_type == CLIENT_TYPE_RX) {
        l_vhost_client->client.vhost_net_app_handler.poll_func_handler = uvhost_poll_client_rx;
    }

    //TODO uvhost_delete_Vhost_Client(vhost_client);

    return E_UVHOST_OK;
}

int
uvhost_init_control_communication(Vhost_Client *vhost_client) {

    Vhost_Client *const l_vhost_client = vhost_client;
    UVHOST_H_RET_VAL ret_val = E_UVHOST_OK;

    if (!vhost_client) {
        return E_UVHOST_ERR_FARG;
    }

    ret_val = uvhost_vhost_init_control_msgs(l_vhost_client);
    if (ret_val != E_UVHOST_OK) {
        return ret_val;
    }

    return E_UVHOST_OK;
}

static int inline
uvhost_vhost_init_control_msgs(Vhost_Client *vhost_client) {

    Client *l_client = NULL ;
    Vhost_Client *const l_vhost_client = vhost_client;
    CLIENT_H_RET_VAL client_ret_val = E_CLIENT_OK;
    VIRT_QUEUE_H_RET_VAL virt_queue_ret_val = E_VIRT_QUEUE_OK;

    if (!vhost_client) {
        return E_UVHOST_ERR_FARG;
    }

    l_client = &(l_vhost_client)->client;

    if (!l_client->socket || (strlen(l_client->socket_path) == 0)) {
        return E_UVHOST_ERR_FARG;
    }

    client_ret_val = client_vhost_ioctl(l_client, VHOST_USER_SET_OWNER, 0);
    if (client_ret_val != E_CLIENT_OK) {
        return E_UVHOST_ERR;
    }

    client_ret_val = (client_vhost_ioctl(l_client, VHOST_USER_GET_FEATURES,
               &l_vhost_client->features));
    if (client_ret_val != E_CLIENT_OK) {
        return E_UVHOST_ERR;
    }

    client_ret_val = (client_vhost_ioctl(l_client, VHOST_USER_SET_MEM_TABLE,
               &l_vhost_client->mem));
    if (client_ret_val != E_CLIENT_OK) {
        return E_UVHOST_ERR;
    }

    virt_queue_ret_val = virt_queue_set_host_virtq_table(l_vhost_client->sh_mem_virtq_table,
                VHOST_CLIENT_VRING_MAX_VRINGS, l_client);

    return E_UVHOST_OK;
}


static inline int
send_packet(Vhost_Client *vhost_client, void *src_buf, size_t src_buf_len) {

    VIRT_QUEUE_H_RET_VAL virt_queue_ret_val = E_VIRT_QUEUE_OK;

    virt_queue_ret_val =virt_queue_put_tx_virt_queue(vhost_client->virtq_control,
            VHOST_CLIENT_VRING_IDX_TX, src_buf, src_buf_len);

    return virt_queue_ret_val;
}

static inline int
map_virt_queue_ret_val_to_main_val(VIRT_QUEUE_H_RET_VAL virt_queue_ret_val) {

    switch (virt_queue_ret_val) {
        case E_VIRT_QUEUE_OK:
            return EXIT_SUCCESS;
            break;

        case E_VIRT_QUEUE_ERR_FARG:
            return EXIT_SUCCESS + 10;
            break;

        case E_VIRT_QUEUE_ERR_SEND_PACKET:
            return EXIT_SUCCESS + 20;
            break;

        case E_VIRT_QUEUE_ERR_ALLOC_PACKET:
            return EXIT_SUCCESS + 30;
            break;

        case E_VIRT_QUEUE_ERR_RECV_PACKET:
            return EXIT_SUCCESS + 40;
            break;

        default:
            return EXIT_SUCCESS + 1000;
            break;
    };

}


int
uvhost_poll_client_tx(void *context, void *src_buf , size_t *src_buf_len) {

    Vhost_Client *vhost_client = NULL;
    VHOST_CLIENT_VRING vq_id = VHOST_CLIENT_VRING_IDX_TX;
    VIRT_QUEUE_H_RET_VAL virt_queue_ret_val = E_VIRT_QUEUE_OK;

    if (!context || !src_buf || src_buf_len == 0) {
        return map_virt_queue_ret_val_to_main_val(E_VIRT_QUEUE_ERR_FARG);
    }

    vhost_client = (Vhost_Client *) context;
    virt_queue_process_used_tx_virt_queue(vhost_client->virtq_control, vq_id);
    virt_queue_ret_val = send_packet(vhost_client, src_buf, *src_buf_len);
    return map_virt_queue_ret_val_to_main_val(virt_queue_ret_val);

}

static inline int
recv_packet(virtq_control *virtq_control, uint64_t *dst_buf, size_t *dst_buf_len, int *remove_flag) {

    struct virtq_used *used = NULL;
    struct virtq_desc *desc = NULL;
    uint16_t last_used_idx = 0;
    uint64_t num = 0;

    if (!virtq_control || !dst_buf ) {
        return E_UVHOST_ERR_FARG;
    }
    if (*remove_flag) *remove_flag = 0;
    else *remove_flag = 1;

    last_used_idx = virtq_control->last_used_idx;
    used = virtq_control->virtq.used;
    desc = virtq_control->virtq.desc;
    num = virtq_control->virtq.num;

    if (last_used_idx != used->idx) {
        *dst_buf = (uint64_t ) ((uintptr_t)desc[used->ring[last_used_idx %num].id].addr + (uintptr_t)sizeof(struct virtio_net_hdr));
        *dst_buf_len = used->ring[last_used_idx % num].len - sizeof(struct virtio_net_hdr);
    } else {
       *remove_flag = 0;
       return E_VIRT_QUEUE_ERR_RECV_PACKET;
    }

    return E_UVHOST_OK;
}

int
uvhost_poll_client_rx(void *context, void *dst_buf, size_t *dst_buf_len) {

    Vhost_Client *vhost_client = NULL;
    VHOST_CLIENT_VRING vq_id = VHOST_CLIENT_VRING_IDX_RX;
    VIRT_QUEUE_H_RET_VAL virt_queue_ret_val = E_VIRT_QUEUE_OK;
    int remove_flag = 0;

    if (!context || !dst_buf ) {
        return map_virt_queue_ret_val_to_main_val(E_VIRT_QUEUE_ERR_FARG);
    }

    vhost_client = (Vhost_Client *) context;

    virt_queue_put_rx_virt_queue(vhost_client->virtq_control,
            vq_id, ETH_MAX_MTU);
    virt_queue_ret_val = recv_packet((vhost_client->virtq_control[vq_id]),
            (uint64_t *)dst_buf, dst_buf_len, &remove_flag);

    if (remove_flag) {
        virt_queue_process_used_rx_virt_queue(vhost_client->virtq_control, vq_id);
    }



    return map_virt_queue_ret_val_to_main_val(virt_queue_ret_val);
}

