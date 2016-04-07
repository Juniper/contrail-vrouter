
#ifndef VHOST_CLIENT_H
#define VHOST_CLIENT_H

#include "client.h"
#include "vhost_net.h"



struct vhost_client_app_handler {
    void *context;
    tx_rx_packet_handler rx_func_handler;
    tx_rx_packet_handler tx_func_handler;
};

typedef struct Vhost_net_Client {

    VhostUserMemory mem;
    size_t page_size;
    size_t virtq_num;
    // Map RX/TX virtq
    struct uvhost_virtq *sh_mem_virtq_table[VHOST_CLIENT_VRING_MAX_VRINGS];
    struct virtq_control *virtq_control[VHOST_CLIENT_VRING_MAX_VRINGS];
    uint16_t features;
    struct vhost_client_app_handler vhost_net_app_handler;
    struct Client client;
} Vhost_net_Client;

typedef Vhost_net_Client Vhost_Client;


typedef enum {
    E_VHOST_CLIENT_OK = EXIT_SUCCESS,
    E_VHOST_CLIENT_ERR_ALLOC,
    E_VHOST_CLIENT_ERR_SET_SH_MEM,
    E_VHOST_CLIENT_ERR_INIT_COMMUNICATION,
    E_VHOST_CLIENT_ERR_MAP_VIRTQ,
    E_VHOST_CLIENT_ERR_UNK,
    E_VHOST_CLIENT_ERR_FARG,
    E_VHOST_CLIENT_ERR,
    E_VHOST_CLIENT_LAST
} VHOST_CLIENT_H_RET_VAL;


#define vhost_client_safe_free(ptr) safer_free((void**)&(ptr))
static void
safer_free(void **mem) {

    if (mem && *mem) {
        free(*mem);
        *mem = NULL;
    }

    return;
}

int vhost_client_poll_client_tx(void *context, void *src_buf , size_t *src_buf_len);
int vhost_client_poll_client_rx(void *context, void *src_buf , size_t *src_buf_len);

#endif

