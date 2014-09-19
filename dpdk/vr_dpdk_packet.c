/*
 * vr_dpdk_packet.c -- the packet interface
 *
 * Copyright (c) 2014, Juniper Networks, Inc.
 * All rights reserved
 */
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>

#include "vr_queue.h"
#include "vr_dpdk.h"
#include "vr_dpdk_usocket.h"

int dpdk_packet_core_id = -1;
unsigned int packet0_port_id = RTE_MAX_ETHPORTS - 1;

int
vr_dpdk_packet_tx(struct vif_port *port)
{
    int event = 1;
    struct vr_usocket *usockp = (struct vr_usocket *)port->vip_eth;

    if (!usockp)
        return 0;

    vr_usocket_write(usockp, &event, sizeof(event));
    return 0;
}

int
dpdk_packet_io(void)
{
    int ret;

wait_for_connection:
    while (!vr_dpdk.packet_transport);

    ret = vr_usocket_io(vr_dpdk.packet_transport);
    if (ret < 0) {
        vr_dpdk.packet_transport = NULL;
        goto wait_for_connection;
    }

    return ret;
}

void
dpdk_packet_socket_close(void)
{
    unsigned short port_id = packet0_port_id;
    struct vif_port *port;
    void *usockp;

    if (!vr_dpdk.packet_transport)
        return;
    usockp = vr_dpdk.packet_transport;

    vr_dpdk.packet_transport = NULL;

    port = &vr_dpdk.ports[port_id];
    port->vip_eth = NULL;

    vr_usocket_close(usockp);

    return;
}

int
dpdk_packet_socket_init(void)
{
    int ret;
    unsigned short lcore_id;
    unsigned short lcore_count = rte_lcore_count();
    unsigned short port_id = packet0_port_id;
    struct vif_port *port;
    struct lcore_ctx *lcore_ctx;
    void *event_sock;

    vr_dpdk.packet_transport = (void *)vr_usocket(PACKET, RAW);
    if (!vr_dpdk.packet_transport)
        return -1;

    if (lcore_count == 2)
        vr_usocket_non_blocking(vr_dpdk.packet_transport);

    port = &vr_dpdk.ports[port_id];
    port->vip_id = port_id;
    port->vip_nb_tx = 1;
    strncpy(port->vip_name, "pkt0", sizeof(port->vip_name));

    if (!port->vip_tx_ring) {
        port->vip_tx_ring = rte_ring_lookup("pkt0_tx");
        if (!port->vip_tx_ring) {
            port->vip_tx_ring = rte_ring_create("pkt0_tx", VR_DPDK_TX_RING_SZ,
                    SOCKET_ID_ANY, 0);
            if (!port->vip_tx_ring) {
                ret = -ENOMEM;
                goto error;
            }
        }
    }

    RTE_LCORE_FOREACH(lcore_id) {
        lcore_ctx = &vr_dpdk.lcores[lcore_id];
        lcore_ctx->lcore_tx_index[port_id] = 1;
    }

    event_sock = (void *)vr_usocket(EVENT, RAW);
    if (!event_sock) {
        ret = -ENOMEM;
        goto error;
    }

    if (vr_usocket_bind_usockets(vr_dpdk.packet_transport, event_sock))
        goto error;

    port->vip_eth = (struct rte_eth_dev *)event_sock;

    return 0;

error:
    if (vr_dpdk.packet_transport) {
        vr_usocket_close(vr_dpdk.packet_transport);
        vr_dpdk.packet_transport = NULL;
    }

    return ret;
}
