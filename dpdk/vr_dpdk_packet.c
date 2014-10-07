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
vr_dpdk_packet_tx(void)
{
    int event = 1;

    if (vr_dpdk.event_sock) {
        vr_usocket_write(vr_dpdk.event_sock, (unsigned char*)&event, sizeof(event));
    }

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
    void *usockp;

    if (!vr_dpdk.packet_transport)
        return;
    usockp = vr_dpdk.packet_transport;

    vr_dpdk.packet_transport = NULL;

    vr_usocket_close(usockp);

    return;
}

int
dpdk_packet_socket_init(void)
{
    int ret;
    unsigned short lcore_count = rte_lcore_count();

    vr_dpdk.packet_transport = (void *)vr_usocket(PACKET, RAW);
    if (!vr_dpdk.packet_transport)
        return -1;

    if (lcore_count == 2)
        vr_usocket_non_blocking(vr_dpdk.packet_transport);

    if (!vr_dpdk.packet_ring) {
        vr_dpdk.packet_ring = rte_ring_lookup("pkt0_tx");
        if (!vr_dpdk.packet_ring) {
            vr_dpdk.packet_ring = rte_ring_create("pkt0_tx", VR_DPDK_TX_RING_SZ,
                    SOCKET_ID_ANY, 0);
            if (!vr_dpdk.packet_ring) {
                ret = -ENOMEM;
                goto error;
            }
        }
    }

    vr_dpdk.event_sock = (void *)vr_usocket(EVENT, RAW);
    if (!vr_dpdk.event_sock) {
        ret = -ENOMEM;
        goto error;
    }

    if (vr_usocket_bind_usockets(vr_dpdk.packet_transport, vr_dpdk.event_sock))
        goto error;

    return 0;

error:
    if (vr_dpdk.packet_transport) {
        vr_usocket_close(vr_dpdk.packet_transport);
        vr_dpdk.packet_transport = NULL;
    }

    return ret;
}
