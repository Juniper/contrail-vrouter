/*
 * Copyright (C) 2016 Semihalf.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * vr_dpdk_tapdev.c -- DPDK tap device
 *
 */

#include "vr_dpdk.h"
#include "vhost.h"
// #include "vr_packet.h"

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_port_ring.h>
#include <rte_malloc.h>

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

/*
 * vr_dpdk_tapdev_init - initializes TAP device using specified Ethernet port.
 *
 * Returns 0 on success, < 0 otherwise.
 */
int
vr_dpdk_tapdev_init(struct vr_interface *vif)
{
    int i, fd;
    struct vr_dpdk_tapdev *tapdev = NULL;
    struct ifreq ifr;
    struct sockaddr_nl tap_nl_addr;

    RTE_LOG(INFO, VROUTER, "    creating TAP device %s\n", vif->vif_name);

    /* Find an empty TAP slot. */
    for (i = 0; i < VR_DPDK_MAX_TAP_INTERFACES; i++) {
        if (vr_dpdk.tapdevs[i].tapdev_fd <= 0) {
            tapdev = &vr_dpdk.tapdevs[i];
            break;
        }
    }
    if (tapdev == NULL) {
        RTE_LOG(ERR, VROUTER, "    error allocating TAP device %s\n",
            vif->vif_name);
        return -ENOMEM;
    }

    /* Open TUN device. */
    fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd == -1) {
        RTE_LOG(ERR, VROUTER, "    error opening TAP device %s: %s (%d)\n",
            vif->vif_name, rte_strerror(errno), errno);
        goto error;
    }

    /* Create TAP interface. */
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, (char *)vif->vif_name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        RTE_LOG(ERR, VROUTER, "    error creating TAP interface %s: %s (%d)\n",
            vif->vif_name, rte_strerror(errno), errno);
        goto error;
    }

    /* Enable TAP device. */
    vif->vif_os = tapdev;
    tapdev->tapdev_vif = vif;
    synchronize_rcu();
    tapdev->tapdev_fd = fd;

    /* Create tap netlink socket for link up/down mtu change notifications */
    if (vif_is_vhost(vif) && vr_dpdk.tap_nl_fd <= 0) {
        vr_dpdk.tap_nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (vr_dpdk.tap_nl_fd < 0) {
            RTE_LOG(ERR, VROUTER, "    error creating tap netlink socket\n");
            goto error;
        }

        memset ((void *) &tap_nl_addr, 0, sizeof (tap_nl_addr));
        tap_nl_addr.nl_family = AF_NETLINK;
        tap_nl_addr.nl_pid = getpid ();
        tap_nl_addr.nl_groups = RTMGRP_LINK;
        if (bind(vr_dpdk.tap_nl_fd,
                    (struct sockaddr *) &tap_nl_addr, sizeof (tap_nl_addr)) < 0) {
            RTE_LOG(ERR, VROUTER, "    error binding tap netlink socket\n");
            goto error;
        }
    }

    return 0;

error:
    if (tapdev->tapdev_fd > 0) {
        close(tapdev->tapdev_fd);
        tapdev->tapdev_fd = -1;
    }

    if (vr_dpdk.tap_nl_fd > 0) {
        close(vr_dpdk.tap_nl_fd);
        vr_dpdk.tap_nl_fd = -1;
    }

    return -EINVAL;
}

/*
 * vr_dpdk_tapdev_release - release TAP device.
 *
 * Returns 0 on success, < 0 otherwise.
 */
int
vr_dpdk_tapdev_release(struct vr_interface *vif)
{
    unsigned lcore_id;
    struct rte_mbuf *mbuf;
    struct vr_dpdk_tapdev *tapdev = vif->vif_os;
    int fd;

    if (tapdev != NULL)
        fd = tapdev->tapdev_fd;
    else
        return 0;

    RTE_LOG(INFO, VROUTER, "    releasing vif %u TAP device %s\n",
            vif->vif_idx, vif->vif_name);

    if (fd > 0) {
        tapdev->tapdev_fd = -1;
        synchronize_rcu();
        close(fd);
    }

    vif->vif_os = NULL;
    tapdev->tapdev_vif = NULL;

    /* Drop RX and TX mbufs. */
    if (tapdev->tapdev_rx_ring) {
        while (rte_ring_sc_dequeue(tapdev->tapdev_rx_ring,
                    (void **)&mbuf) == 0) {
            rte_pktmbuf_free(mbuf);
        }
    }

    RTE_LCORE_FOREACH(lcore_id) {
        if (tapdev->tapdev_tx_rings[lcore_id]) {
            while (rte_ring_sc_dequeue(tapdev->tapdev_tx_rings[lcore_id],
                        (void **)&mbuf) == 0) {
                rte_pktmbuf_free(mbuf);
            }
        }
    }

    if (vif_is_vhost(vif) && vr_dpdk.tap_nl_fd > 0) {
        close(vr_dpdk.tap_nl_fd);
        vr_dpdk.tap_nl_fd = -1;
    }

    return 0;
}

/*
 * dpdk_tapdev_rx_queue_release - release TAP RX queue.
 */
static void
dpdk_tapdev_rx_queue_release(unsigned lcore_id,
        unsigned queue_index __attribute__((unused)),
        struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif->vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params
                        = &lcore->lcore_rx_queue_params[vif->vif_idx];

    /* Free the queue. */
    if (rx_queue->rxq_ops.f_free(rx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u TAP device RX queue\n",
                    lcore_id);
    }

    /* Reset the queue. */
    vrouter_put_interface(rx_queue->q_vif);
    memset(rx_queue, 0, sizeof(*rx_queue));
    memset(rx_queue_params, 0, sizeof(*rx_queue_params));
}


/*
 * vr_dpdk_tapdev_rx_queue_init - init TAP RX queue.
 *
 * Returns queue pointer on success, NULL otherwise.
 */
struct vr_dpdk_queue *
vr_dpdk_tapdev_rx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned queue_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    const unsigned socket_id = rte_lcore_to_socket_id(lcore_id);
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_tapdev *tapdev = vif->vif_os;
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params
                    = &lcore->lcore_rx_queue_params[vif_idx];

    /* Init queue. */
    rx_queue->rxq_ops = rte_port_ring_reader_ops;
    rx_queue->q_queue_h = NULL;
    rx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* Allocate RX ring if needed. */
    if (tapdev->tapdev_rx_ring == NULL) {
        tapdev->tapdev_rx_ring = vr_dpdk_ring_allocate(lcore_id,
            "tapdev_rx_ring", VR_DPDK_RX_RING_SZ,
            RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (tapdev->tapdev_rx_ring == NULL)
            goto error;
    }

    /* Create the queue. */
    struct rte_port_ring_reader_params reader_params = {
        .ring = tapdev->tapdev_rx_ring,
    };
    rx_queue->q_queue_h = rx_queue->rxq_ops.f_create(&reader_params,
                                                        socket_id);
    if (rx_queue->q_queue_h == NULL)
        goto error;

    /* Store queue params. */
    rx_queue_params->qp_release_op = &dpdk_tapdev_rx_queue_release;
    rx_queue_params->qp_ring.ring_p = tapdev->tapdev_rx_ring;

    return rx_queue;

error:
    RTE_LOG(ERR, VROUTER,
        "    error initializing tapdev %s RX queue\n", vif->vif_name);
    return NULL;
}

/*
 * dpdk_tapdev_tx_queue_release - release TAP TX queue.
 */
static void
dpdk_tapdev_tx_queue_release(unsigned lcore_id, unsigned queue_index,
        struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *tx_queue =
        &lcore->lcore_tx_queues[vif->vif_idx][queue_index];
    struct vr_dpdk_queue_params *tx_queue_params
        = &lcore->lcore_tx_queue_params[vif->vif_idx][queue_index];

    tx_queue->txq_ops.f_tx = NULL;
    rte_wmb();

    /* Flush and free the queue. */
    if (tx_queue->txq_ops.f_free(tx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u TAP device TX queue\n",
                    lcore_id);
    }

    /* Reset the queue. */
    vrouter_put_interface(tx_queue->q_vif);
    memset(tx_queue, 0, sizeof(*tx_queue));
    memset(tx_queue_params, 0, sizeof(*tx_queue_params));
}

/*
 * vr_dpdk_tapdev_tx_queue_init - init TAP TX queue.
 *
 * Returns queue pointer on success, NULL otherwise.
 */
struct vr_dpdk_queue *
vr_dpdk_tapdev_tx_queue_init(unsigned lcore_id, struct vr_interface *vif,
    unsigned queue_id)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    const unsigned socket_id = rte_lcore_to_socket_id(lcore_id);
    unsigned vif_idx = vif->vif_idx;
    struct vr_dpdk_tapdev *tapdev = vif->vif_os;
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx][0];
    struct vr_dpdk_queue_params *tx_queue_params
                    = &lcore->lcore_tx_queue_params[vif_idx][0];

    /* Init queue. */
    tx_queue->txq_ops = rte_port_ring_writer_ops;
    tx_queue->q_queue_h = NULL;
    tx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* Allocate TX ring if needed. */
    if (tapdev->tapdev_tx_rings[lcore_id] == NULL) {
        tapdev->tapdev_tx_rings[lcore_id] = vr_dpdk_ring_allocate(lcore_id,
            "tapdev_tx_ring", VR_DPDK_TX_RING_SZ,
            RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (tapdev->tapdev_tx_rings[lcore_id] == NULL)
            goto error;
    }

    /* Create the queue. */
    struct rte_port_ring_writer_params writer_params = {
        .ring = tapdev->tapdev_tx_rings[lcore_id],
        .tx_burst_sz = VR_DPDK_TX_BURST_SZ,
    };
    tx_queue->q_queue_h = tx_queue->txq_ops.f_create(&writer_params,
                                                        socket_id);
    if (tx_queue->q_queue_h == NULL)
        goto error;

    /* Store queue params. */
    tx_queue_params->qp_release_op = &dpdk_tapdev_tx_queue_release;
    tx_queue_params->qp_ring.ring_p = tapdev->tapdev_tx_rings[lcore_id];

    return tx_queue;

error:
    RTE_LOG(ERR, VROUTER,
        "    error initializing tapdev %s TX queue\n", vif->vif_name);
    return NULL;
}

/*
 * vr_dpdk_tapdev_rx_burst - RX a burst of packets from the TAP device.
 *
 * Returns number of actual packets received, or 0 otherwise.
 */
unsigned
vr_dpdk_tapdev_rx_burst(struct vr_dpdk_tapdev *tapdev, struct rte_mbuf **mbufs,
    unsigned num)
{
    int i, fd;
    unsigned ret = 0;
    struct rte_mbuf *mbuf;
    struct vr_interface *vif;
    struct vr_interface_stats *stats;
    unsigned lcore_id = rte_lcore_id();
    ssize_t len;

    fd = tapdev->tapdev_fd;
    if (unlikely(fd <= 0))
        return 0;

    for (i = 0; i < num; i++) {
        vif = tapdev->tapdev_vif;
        stats = vif_get_stats(vif, lcore_id);

        mbuf = rte_pktmbuf_alloc(vr_dpdk.rss_mempool);
        if (unlikely(mbuf == NULL)) {
            stats->vis_dev_inombufs++;
            break;
        }

        /* TODO: need a separate syscall counter for devices. */
        stats->vis_port_isyscalls++;
        len = read(fd, rte_pktmbuf_mtod(mbuf, void *),
                (mbuf->buf_len - rte_pktmbuf_headroom(mbuf)));
        if (unlikely(len <= 0)) {
            /* No packets to receive. */
            rte_pktmbuf_free(mbuf);
            break;
        } else {
            ret++;

            mbuf->pkt_len = mbuf->data_len = len;
            stats->vis_dev_ibytes += len;
            stats->vis_dev_ipackets++;
            mbufs[i] = mbuf;
       }
   }
   return ret;
}

/*
 * vr_dpdk_tapdev_dequeue_burst - dequeue a burst of packets from the TAP device.
 *
 * Returns number of actual packets dequeued, or 0 otherwise.
 */
unsigned
vr_dpdk_tapdev_dequeue_burst(struct vr_dpdk_tapdev *tapdev, struct rte_mbuf **mbufs,
    unsigned num)
{
    int fd;

    fd = tapdev->tapdev_fd;
    if (unlikely(fd <= 0))
        return 0;

    /* Try to RX from the TAP. */
    if (likely(tapdev->tapdev_rx_ring != NULL)) {
        return rte_ring_sc_dequeue_burst(tapdev->tapdev_rx_ring,
                (void **)mbufs, num);
    }
    return 0;
}

/*
 * vr_dpdk_tapdev_tx_burst - TX a burst of packets to the TAP device.
 *
 * Returns number of actual packets sent, or 0 otherwise.
 */
unsigned
vr_dpdk_tapdev_tx_burst(struct vr_dpdk_tapdev *tapdev, struct rte_mbuf **mbufs,
        unsigned num)
{
    int i, fd;
    unsigned ret = 0;
    struct rte_mbuf *mbuf;
    struct vr_interface *vif;
    struct vr_interface_stats *stats;
    unsigned lcore_id = rte_lcore_id();
    ssize_t len;

    fd = tapdev->tapdev_fd;
    if (unlikely(fd <= 0))
        return 0;

    for (i = 0; i < num; i++) {
        vif = tapdev->tapdev_vif;
        stats = vif_get_stats(vif, lcore_id);
        mbuf = mbufs[i];

        /* TODO: need a separate syscall counter for devices. */
        stats->vis_port_osyscalls++;
        len = write(fd, rte_pktmbuf_mtod(mbufs[i], void *),
            rte_pktmbuf_data_len(mbuf));
        if (unlikely(len != (ssize_t)rte_pktmbuf_data_len(mbufs[i]))) {
            /* Error sending packet. */
            stats->vis_dev_oerrors++;
            break;
        } else {
            stats->vis_dev_obytes += len;
            stats->vis_dev_opackets++;
            ret++;
        }
        rte_pktmbuf_free(mbuf);
    }

   return ret;
}

/*
 * vr_dpdk_tapdev_enqueue_burst - enqueue a burst of packets to the TAP device.
 *
 * Returns number of actual packets enqueued, or 0 otherwise.
 */
unsigned
vr_dpdk_tapdev_enqueue_burst(struct vr_dpdk_tapdev *tapdev, struct rte_mbuf **mbufs,
        unsigned num)
{
    int fd;
    unsigned lcore_id = rte_lcore_id();

    fd = tapdev->tapdev_fd;
    if (unlikely(fd <= 0))
        return 0;

    if (likely(tapdev->tapdev_tx_rings[lcore_id] != NULL)) {
        return rte_ring_sp_enqueue_burst(tapdev->tapdev_tx_rings[lcore_id],
            (void **)mbufs, num);
    }

   return 0;
}

/*
 * vr_dpdk_tapdev_rxtx -- RX/TX to/from all the TAP devices.
 *
 * Returns total number of packets processed.
 */
uint64_t
vr_dpdk_tapdev_rxtx(void)
{
    int i, fd;
    struct vr_dpdk_tapdev *tapdev;
    struct rte_mbuf *mbuf;
    struct vr_interface *vif;
    struct vr_interface_stats *stats;
    unsigned lcore_id;
    uint64_t total_pkts = 0;
    unsigned nb_pkts;

    for (i = 0; i < VR_DPDK_MAX_TAP_INTERFACES; i++) {
        tapdev = &vr_dpdk.tapdevs[i];

        fd = tapdev->tapdev_fd;
        if (fd > 0) {
            vif = tapdev->tapdev_vif;
            stats = vif_get_stats(vif, rte_lcore_id());

            /* Try to RX from the TAP. */
            if (likely(tapdev->tapdev_rx_ring != NULL)) {
                nb_pkts = vr_dpdk_tapdev_rx_burst(tapdev, &mbuf, 1);

                if (likely(nb_pkts > 0)) {
                    total_pkts++;
                    if (unlikely(rte_ring_sp_enqueue(tapdev->tapdev_rx_ring,
                        mbuf) != 0)) {
                        rte_pktmbuf_free(mbuf);
                        stats->vis_dev_ierrors++;
                    }
                }
            }

            /* Now try to TX to the TAP. */
            RTE_LCORE_FOREACH(lcore_id) {
                if (likely(tapdev->tapdev_tx_rings[lcore_id] != NULL)) {
                    if (likely(rte_ring_sc_dequeue(
                        tapdev->tapdev_tx_rings[lcore_id],
                        (void **)&mbuf) == 0))
                    {
                        total_pkts++;
                        nb_pkts = vr_dpdk_tapdev_tx_burst(tapdev, &mbuf, 1);

                        if (likely(nb_pkts > 0)) {
                            total_pkts++;
                        } else {
                            rte_pktmbuf_free(mbuf);
                        }
                    }
                } /* if TAP TX ring. */
            } /* for each lcore. */
        } /* if TAP FD. */
    } /* for all TAP devices. */

    return total_pkts;
}

static void vr_dpdk_handle_vhost0_notification(uint32_t mtu, uint32_t if_up)
{
    static int vhost_mtu = 1500; /* Default MTU */
    static int vhost_if_status = 1; /* Default if state */

    struct vr_interface *vif;
    struct vrouter *router = vrouter_get(0);
    struct vr_dpdk_ethdev *ethdev = NULL;
    uint8_t slave_port_id, port_id = 0;
    int ret = 0, i;

    if (router->vr_eth_if)
        ethdev = (struct vr_dpdk_ethdev *)router->vr_eth_if->vif_os;

    if (ethdev == NULL) {
        RTE_LOG(ERR, VROUTER, "%s error: NULL ethdev\n", __func__);
        return;
    }

    port_id = ethdev->ethdev_port_id;

    if (vhost_mtu != mtu) {
        /*
         * TODO: DPDK bond PMD does not implement mtu_set op, so we need to
         * set the MTU manually for all the slaves.
         */
        if (ethdev->ethdev_nb_slaves > 0) {
            RTE_LOG(INFO, VROUTER, "Changing bond eth device %" PRIu8 " MTU\n", port_id);

            rte_eth_devices[port_id].data->mtu = mtu;
            for (i = 0; i < ethdev->ethdev_nb_slaves; i++) {
                slave_port_id = ethdev->ethdev_slaves[i];
                RTE_LOG(INFO, VROUTER,
                        "    changing bond member eth device %" PRIu8 " MTU to %u\n",
                        slave_port_id, mtu);

                ret =  rte_eth_dev_set_mtu(slave_port_id, mtu);
                if (ret < 0) {
                    /*
                     * Do not return error as some NICs (such as X710) do not allow setting 
                     * the MTU while the NIC is up and running. The max_rx_pkt_len is anyway
                     * set to support jumbo frames, so continue further here to set vif_mtu.
                     */
                    RTE_LOG(DEBUG, VROUTER,
                            "    error changing bond member eth device %" PRIu8 " MTU: %s (%d)\n",
                            slave_port_id, rte_strerror(-ret), -ret);
                }
            }
        } else {
            RTE_LOG(INFO, VROUTER, "Changing eth device MTU to %u\n", mtu);

            ret =  rte_eth_dev_set_mtu(port_id, mtu);
            if (ret < 0) {
                /*
                 * Do not return error as some NICs (such as X710) do not allow setting 
                 * the MTU while the NIC is up and running. The max_rx_pkt_len is anyway
                 * set to support jumbo frames, so continue further here to set vif_mtu.
                 */
                RTE_LOG(DEBUG, VROUTER,
                        "Error changing eth device MTU: %s (%d)\n",
                        rte_strerror(-ret), -ret);
            }
        }

        /* On success, inform vrouter about new MTU */
        for (i = 0; i < router->vr_max_interfaces; i++) {
            vif = __vrouter_get_interface(router, i);
            if (vif && (vif->vif_type == VIF_TYPE_PHYSICAL)) {
               /* Ethernet header size */
               mtu += sizeof(struct vr_eth);
               if (vr_dpdk.vlan_tag != VLAN_ID_INVALID) {
                   /* 802.1q header size */
                   mtu += sizeof(uint32_t);
               }
               vif->vif_mtu = mtu;
               if (vif->vif_bridge)
                   vif->vif_bridge->vif_mtu = mtu;
            }
        }

        /* Save the new MTU */
        vhost_mtu = mtu;
    }

    if (vhost_if_status != if_up) {

        ret = 0;

        RTE_LOG(INFO, VROUTER, "Configuring eth device %" PRIu8 " %s\n",
                        port_id, if_up ? "UP" : "DOWN");

        if (if_up)
            ret = rte_eth_dev_start(port_id);
        else
            rte_eth_dev_stop(port_id);

        if (ret < 0) {
            RTE_LOG(ERR, VROUTER, "Configuring eth device %" PRIu8 " UP "
                        "failed (%d)\n", port_id, ret);
        }

        /* Save the new IF state */
        vhost_if_status = if_up;
    }
}

void vr_dpdk_tapdev_handle_notifications(void)
{
    int32_t status;
    char buf[4096];
    struct iovec iov = {buf, sizeof buf};
    struct sockaddr_nl snl;
    struct msghdr msg = {(void *) &snl, sizeof snl, &iov, 1, NULL, 0, 0};
    struct nlmsghdr *h;
    struct ifinfomsg *ifi;

    status = recvmsg(vr_dpdk.tap_nl_fd, &msg, MSG_DONTWAIT);
    if (status <= 0) {
        /* Nothing to process */
        return;
    }

    for (h = (struct nlmsghdr *) buf; NLMSG_OK (h, (unsigned int) status);
         h = NLMSG_NEXT (h, status))
    {
        /* Finish reading */
        if (h->nlmsg_type == NLMSG_DONE)
          return;

        /* Message is some kind of error */
        if (h->nlmsg_type == NLMSG_ERROR) {
            RTE_LOG(ERR, VROUTER, "read_netlink: Message error\n");
            return; /* Error */
        }

        if (h->nlmsg_type == RTM_NEWLINK) {
            int len;
            struct rtattr *attribute;
            char *ifname = NULL;
            uint32_t mtu = 0;

            ifi = NLMSG_DATA (h);

            len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));

            /* loop over all attributes for the NEWLINK message */
            for (attribute = IFLA_RTA(ifi); RTA_OK(attribute, len);
                                           attribute = RTA_NEXT(attribute, len))
            {
                switch(attribute->rta_type) {
                    case IFLA_IFNAME:
                        ifname = (char*) RTA_DATA(attribute);
                        break;
                    case IFLA_MTU:
                        mtu = *(uint32_t*) RTA_DATA(attribute);
                        break;
                    default:
                        break;
                }
            }

            if (ifname && (strncmp(ifname, VHOST_IFNAME, (strlen(VHOST_IFNAME) + 1)) == 0)) {
                RTE_LOG(INFO, VROUTER, "Notification received for vhost0\n");
                vr_dpdk_handle_vhost0_notification
                                 (mtu, (ifi->ifi_flags & IFF_UP));
            }
        }
    }
}
