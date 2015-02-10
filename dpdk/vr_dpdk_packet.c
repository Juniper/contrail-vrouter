/*
 * vr_dpdk_packet.c -- the packet interface
 *
 * Copyright (c) 2014, Juniper Networks, Inc.
 * All rights reserved
 */
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#include "vr_queue.h"
#include "vr_dpdk.h"
#include "vr_dpdk_usocket.h"

int dpdk_packet_core_id = -1;

int
vr_dpdk_packet_tx(void)
{
    int ret;
    uint64_t event = 1;
    unsigned int lcore_id = rte_lcore_id();
    struct vr_dpdk_lcore *lcorep = vr_dpdk.lcores[lcore_id];

    if (lcorep->lcore_event_sock) {
        ret = vr_usocket_write(lcorep->lcore_event_sock, (unsigned char *)&event,
                sizeof(event));
        if (ret < 0) {
            vr_usocket_close(lcorep->lcore_event_sock);
            lcorep->lcore_event_sock = NULL;
        }
    }

    return 0;
}

int
dpdk_packet_io(void)
{
    int ret;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[rte_lcore_id()];

wait_for_connection:
    while (!vr_dpdk.packet_transport) {
        /* handle an IPC command */
        if (unlikely(vr_dpdk_lcore_cmd_handle(lcore)))
            return -1;
        usleep(VR_DPDK_SLEEP_SERVICE_US);
    }

    ret = vr_usocket_io(vr_dpdk.packet_transport);
    if (ret < 0) {
        vr_dpdk.packet_transport = NULL;
        /* handle an IPC command */
        if (unlikely(vr_dpdk_lcore_cmd_handle(lcore)))
            return -1;
        usleep(VR_DPDK_SLEEP_SERVICE_US);
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
    int ret, i;
    unsigned int netlink_lcore_id = rte_lcore_id();
    unsigned short lcore_count = rte_lcore_count();
    struct vr_dpdk_lcore *lcorep;

    vr_dpdk.packet_transport = (void *)vr_usocket(PACKET, RAW);
    if (!vr_dpdk.packet_transport)
        return -1;

    if (lcore_count == VR_DPDK_MIN_LCORES)
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

    for (i = 0; i < lcore_count; i++) {
        if (i == netlink_lcore_id)
            continue;

        lcorep = vr_dpdk.lcores[i];
        lcorep->lcore_event_sock = (void *)vr_usocket(EVENT, RAW);
        if (!lcorep->lcore_event_sock) {
            ret = -ENOMEM;
            goto error;
        }

        if (vr_usocket_bind_usockets(vr_dpdk.packet_transport,
                    lcorep->lcore_event_sock))
            goto error;
    }


    return 0;

error:
    if (vr_dpdk.packet_transport) {
        vr_usocket_close(vr_dpdk.packet_transport);
        vr_dpdk.packet_transport = NULL;
    }

    return ret;
}
