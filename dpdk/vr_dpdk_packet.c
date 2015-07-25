/*
 * vr_dpdk_packet.c -- the packet interface
 *
 * Copyright (c) 2014, Juniper Networks, Inc.
 * All rights reserved
 */

#include "vr_dpdk.h"
#include "vr_queue.h"
#include "vr_dpdk_usocket.h"

#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

int dpdk_packet_core_id = -1;

void
vr_dpdk_packet_wakeup(void)
{
    if (likely(vr_dpdk.packet_event_sock != NULL)) {
        if (vr_usocket_eventfd_write(vr_dpdk.packet_event_sock) < 0) {
            vr_usocket_close(vr_dpdk.packet_event_sock);
            vr_dpdk.packet_event_sock = NULL;
        }
    }
}

/* Work callback called on packet lcore */
void
vr_dpdk_packet_work_cb(void (*fn)(void *), void *arg)
{
    rcu_read_lock();
    fn(arg);
    rcu_read_unlock();
    /* nothing to free since we pass two arguments */
}

/* RCU callback called on packet lcore */
void
vr_dpdk_packet_rcu_cb(struct rcu_head *rh)
{
    struct vr_dpdk_rcu_cb_data *cb_data;

    cb_data = CONTAINER_OF(rcd_rcu, struct vr_dpdk_rcu_cb_data, rh);

    /* Call the user call back */
    cb_data->rcd_user_cb(cb_data->rcd_router, cb_data->rcd_user_data);
    vr_free(cb_data, VR_DEFER_OBJECT);
}

int
dpdk_packet_io(void)
{
    int ret;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[rte_lcore_id()];

wait_for_connection:
    RTE_LOG(DEBUG, VROUTER, "%s[%lx]: waiting for packet transport\n",
                __func__, pthread_self());

    rcu_thread_offline();
    while (!vr_dpdk.packet_transport) {
        /* handle an IPC command */
        if (unlikely(vr_dpdk_lcore_cmd_handle(lcore)))
            return -1;
        usleep(VR_DPDK_SLEEP_SERVICE_US);
    }

    RTE_LOG(DEBUG, VROUTER, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                ((struct vr_usocket *)vr_dpdk.packet_transport)->usock_fd);
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

    /* close and free up the memory both for packet usock and binded event usock */
    usockp = vr_dpdk.packet_transport;
    vr_dpdk.packet_transport = NULL;
    vr_dpdk.packet_event_sock = NULL;
    vr_usocket_close(usockp);

    return;
}

int
dpdk_packet_socket_init(void)
{
    void *event_sock = NULL;
    int err;

    vr_dpdk.packet_transport = (void *)vr_usocket(PACKET, RAW);
    if (!vr_dpdk.packet_transport)
        return -1;

    if (!vr_dpdk.packet_ring) {
        vr_dpdk.packet_ring = rte_ring_lookup("packet_tx");
        if (!vr_dpdk.packet_ring) {
            /* multi-producers single-consumer ring */
            vr_dpdk.packet_ring = rte_ring_create("packet_tx", VR_DPDK_TX_RING_SZ,
                    SOCKET_ID_ANY, RING_F_SC_DEQ);
            if (!vr_dpdk.packet_ring) {
                RTE_LOG(ERR, VROUTER, "    error creating packet ring\n");
                goto error;
            }
        }
    }

    /* create and bind event usock to wake up the packet lcore */
    event_sock = (void *)vr_usocket(EVENT, RAW);
    if (!event_sock)
        goto error;

    if (vr_usocket_bind_usockets(vr_dpdk.packet_transport,
                event_sock))
        goto error;
    vr_dpdk.packet_event_sock = event_sock;

    return 0;

error:
    err = errno;
    if (event_sock)
        vr_usocket_close(event_sock);
    vr_usocket_close(vr_dpdk.packet_transport);
    vr_dpdk.packet_transport = NULL;
    errno = err;

    return -ENOMEM;
}
