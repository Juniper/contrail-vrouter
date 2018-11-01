/*ome headers, functions and message definitions are copied from
 * reference file (virtio_ring.h)
    *  *
    *   * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
    *   */
#ifndef VHOST_NET_H
#define VHOST_NET_H

#include <stdlib.h>

typedef enum {

    E_VHOST_NET_OK = EXIT_SUCCESS,
    E_VHOST_NET_ERR_FARG,
    E_VHOST_NET_ERR_SEND_PACKET,
    E_VHOST_NET_ERR_ALLOC,
    E_VHOST_NET_ERR_ALLOC_PACKET,
    E_VHOST_NET_ERR_RECV_PACKET,
    E_VHOST_NET_ERR_INIT_COMMUNICATION,
    E_VHOST_NET_ERR_SET_SH_MEM,
    E_VHOST_NET_ERR_MAP_VIRTQ,
    E_VHOST_NET_ERR_UNK,

} vhost_net_state;

typedef int (*tx_rx_packet_handler)(void *context, void *src_buf, size_t *src_buf_len);

typedef struct vhost_net {
    tx_rx_packet_handler rx;
    tx_rx_packet_handler tx;
    void *context;

} vhost_net;

int init_vhost_net(vhost_net **client,  const char *vhost_client_path, int mode);
int deinit_vhost_net(vhost_net *client);
#endif

