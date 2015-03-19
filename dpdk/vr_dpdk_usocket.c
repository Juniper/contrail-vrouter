/*
 * vr_dpdk_usocket.c -- library to deal with packet0 and netlink tcp/unix
 * sockets
 *
 * Copyright(c) 2014, Juniper Networks Inc.
 * All rights reserved
 */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/eventfd.h>

#include <urcu-qsbr.h>

#include <netinet/in.h>

#include <linux/netlink.h>

#include "vr_queue.h"
#include "vr_dpdk_usocket.h"
#include "vr_message.h"
#include "vr_dpdk.h"

#include <rte_hexdump.h>
#include <rte_timer.h>

#define INFINITE_TIMEOUT    -1

extern void dpdk_burst_rx(unsigned int, struct rte_mbuf *[],
                struct vr_interface *, const char *, unsigned int);
extern struct nlmsghdr *dpdk_nl_message_hdr(struct vr_message *);
extern unsigned int dpdk_nl_message_len(struct vr_message *);

static int vr_usocket_accept(struct vr_usocket *);
static int vr_usocket_connect(struct vr_usocket *);
static int vr_usocket_bind(struct vr_usocket *);
static int usock_write(struct vr_usocket *);
static int usock_read_init(struct vr_usocket *);

/*
 * mark the error in socket for somebody to process/see
 */
static void
usock_set_error(struct vr_usocket *usockp, int error)
{
    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d error %d\n", __func__, pthread_self(),
            usockp->usock_fd, error);
    usockp->usock_error = error;
    usockp->usock_errno = errno;

    return;
}

/*
 * free the poll descriptor array, if it was allocated
 */
static void
usock_deinit_poll(struct vr_usocket *usockp)
{
    if (!usockp)
        return;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(), usockp->usock_fd);
    if (usockp->usock_pfds) {
        vr_free(usockp->usock_pfds);
        usockp->usock_pfds = NULL;
    }

    return;
}

/*
 * for both netlink and packet protocol sockets, we will need to poll. in case
 * of netlink, the poll in on tcp sockets to accept a connection (from agent,
 * utilities etc.:). for packet socket, the poll is on unix socket to receive
 * packets from agent and to be passed to vrouter. packet sockets also will
 * have an event usocket to dequeue packets from the pkt0_mbuf_ring, where
 * packets to be trapped will be enqueued.
 *
 * alloc the poll array
 */
static int
usock_init_poll(struct vr_usocket *usockp)
{
    unsigned int i;
    unsigned int proto;

    if (!usockp)
        return -EINVAL;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(), usockp->usock_fd);
    proto = usockp->usock_proto;
    if ((proto != NETLINK) && (proto != PACKET)) {
        usock_set_error(usockp, -EINVAL);
        goto error_return;
    }

    if (!usockp->usock_max_cfds) {
        usock_set_error(usockp, -EINVAL);
        goto error_return;
    }

    if (!usockp->usock_pfds) {
        usockp->usock_pfds = vr_zalloc(sizeof(struct pollfd) *
                usockp->usock_max_cfds + 1);
        if (!usockp->usock_pfds) {
            usock_set_error(usockp, -ENOMEM);
            goto error_return;
        }

        for (i = 1; i <= usockp->usock_max_cfds; i++) {
            usockp->usock_pfds[i].fd = -1;
        }
    }

    return 0;

error_return:
    return usockp->usock_error;
}

/*
 * bind a child socket to the parent. binding in this context means adding
 * a child usocket to parent poll list. an example where this will be required
 * is when one has created an event usocket. An event usocket by itself cannot
 * do anything useful in the context of dpdk vrouter application. Hence it needs
 * to be bound to the parent socket that does something useful, in this case
 * the packet socket. Another example is that of netlink socket. when thexi
 * netlink socket accepts new connection and the new connected socket has to be
 * polled, in which case we will need to bind it to the parent socket poll list
 */
static int
usock_bind_usockets(struct vr_usocket *parent, struct vr_usocket *child)
{
    unsigned int i;
    int ret;
    struct vr_usocket *child_pair;

    if (parent->usock_state == LIMITED)
        return -ENOSPC;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: parent FD %d child FD %d\n", __func__,
            pthread_self(), parent->usock_fd, child->usock_fd);

    if (child->usock_proto == EVENT) {
        child_pair = vr_usocket(EVENT, RAW);
        if (!child_pair)
            return -ENOMEM;

        RTE_LOG(DEBUG, USOCK, "%s[%lx]: parent FD %d closing child FD %d\n",
                    __func__, pthread_self(), parent->usock_fd, child->usock_fd);
        close(child->usock_fd);
        child->usock_fd = child_pair->usock_fd;
        child = child_pair;
    }

    ret = usock_init_poll(parent);
    if (ret)
        return ret;

    if (!parent->usock_children) {
        parent->usock_children = vr_zalloc(sizeof(struct vr_usocket *) *
                USOCK_MAX_CHILD_FDS + 1);
        if (!parent->usock_children) {
            usock_set_error(parent, -ENOMEM);
            return -ENOMEM;
        }
    }

    child->usock_parent = parent;
    parent->usock_cfds++;
    if (parent->usock_cfds == USOCK_MAX_CHILD_FDS)
        parent->usock_state = LIMITED;

    for (i = 1; i <= parent->usock_max_cfds; i++) {
        if (!parent->usock_children[i]) {
            parent->usock_children[i] = child;
            parent->usock_pfds[i].fd = child->usock_fd;
            parent->usock_pfds[i].events = POLLIN;
            child->usock_child_index = i;
            break;
        }
    }

    if (child->usock_proto == EVENT)
        child->usock_state = READING_DATA;

    usock_read_init(child);

    return 0;
}

int
vr_usocket_bind_usockets(void *usock1, void *usock2)
{
    struct vr_usocket *parent = (struct vr_usocket *)usock1;
    struct vr_usocket *child = (struct vr_usocket *)usock2;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: usock1 FD %d usock2 FD %d\n", __func__,
            pthread_self(), parent->usock_fd, child->usock_fd);
    return usock_bind_usockets(parent, child);
}

static int
usock_clone(struct vr_usocket *parent, int cfd)
{
    struct vr_usocket *child;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: parent FD %d cfd %d\n", __func__,
            pthread_self(), parent->usock_fd, cfd);
    child = vr_zalloc(sizeof(struct vr_usocket));
    if (!child) {
        usock_set_error(parent, -ENOMEM);
        goto error_return;
    }

    child->usock_rx_buf = vr_malloc(USOCK_RX_BUF_LEN);
    if (!child->usock_rx_buf) {
        usock_set_error(parent, -ENOMEM);
        goto error_return;
    }
    child->usock_buf_len = USOCK_RX_BUF_LEN;

    child->usock_type = parent->usock_type;
    child->usock_proto = parent->usock_proto;
    child->usock_fd = cfd;

    if (usock_bind_usockets(parent, child))
        goto error_return;

    return 0;

error_return:
    if (child) {
        if (child->usock_rx_buf)
            vr_free(child->usock_rx_buf);
        vr_free(child);
    }

    return parent->usock_error;
}


static void
usock_unbind(struct vr_usocket *child)
{
    struct vr_usocket *parent;

    if (!child)
        return;

    parent = child->usock_parent;
    RTE_LOG(DEBUG, USOCK, "%s[%lx]: child FD %d parent %p\n", __func__,
            pthread_self(), child->usock_fd, parent);
    if (!parent)
        return;

    parent->usock_children[child->usock_child_index] = NULL;
    if (parent->usock_pfds)
        parent->usock_pfds[child->usock_child_index].fd = -1;

    parent->usock_disconnects++;
    parent->usock_cfds--;

    child->usock_parent = NULL;

    return;
}

static void
usock_close(struct vr_usocket *usockp)
{
    int i;
    struct vr_usocket *parent;

    RTE_SET_USED(parent);

    if (!usockp)
        return;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(), usockp->usock_fd);
    usock_unbind(usockp);
    usock_deinit_poll(usockp);

    for (i = 0; i < usockp->usock_cfds; i++) {
        usock_close(usockp->usock_children[i]);
    }

    RTE_LOG(DEBUG, USOCK, "%s: closing FD %d\n", __func__, usockp->usock_fd);
    close(usockp->usock_fd);

    if (!usockp->usock_mbuf_pool && usockp->usock_rx_buf) {
        vr_free(usockp->usock_rx_buf);
        usockp->usock_rx_buf = NULL;
    }

    if (usockp->usock_iovec) {
        vr_free(usockp->usock_iovec);
        usockp->usock_iovec = NULL;
    }

    if (usockp->usock_mbuf_pool) {
        /* no api to destroy a pool */
    }

    if (usockp->usock_proto == PACKET) {
        RTE_LOG(DEBUG, USOCK, "%s[%lx]: unlinking %s\n", __func__,
            pthread_self(), VR_PACKET_UNIX_FILE);
        unlink(VR_PACKET_UNIX_FILE);
    }

    usockp->usock_io_in_progress = 0;

    vr_free(usockp);

    return;
}

static int
__usock_write(struct vr_usocket *usockp)
{
    int ret;
    unsigned int len;
    unsigned char *buf;
    struct vr_usocket *parent = NULL;

    if (usockp->usock_proto != EVENT) {
        parent = usockp->usock_parent;
        if (!parent)
            return -1;
    }

    buf = usockp->usock_tx_buf;
    if (!buf || !usockp->usock_write_len)
        return 0;

    len = usockp->usock_write_len;

    buf += usockp->usock_write_offset;
    len -= usockp->usock_write_offset;

retry_write:
#ifdef VR_DPDK_USOCK_DUMP
    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d writing %d bytes\n",
                __func__, pthread_self(), usockp->usock_fd, len);
    rte_hexdump(stdout, "usock buffer dump:", buf, len);
#endif
    ret = write(usockp->usock_fd, buf, len);
    if (ret > 0) {
        usockp->usock_write_offset += ret;
        if (usockp->usock_write_offset == usockp->usock_write_len) {
            /* remove from output poll */
            if (parent)
                parent->usock_pfds[usockp->usock_child_index].events = POLLIN;
            usockp->usock_tx_buf = NULL;
        } else {
            if (parent)
                parent->usock_pfds[usockp->usock_child_index].events = POLLOUT;
        }
    } else if (ret < 0) {
        RTE_LOG(DEBUG, VROUTER, "%s[%lx]: write error FD %d\n", __func__, pthread_self(),
                usockp->usock_fd);
        usock_set_error(usockp, ret);

        if (errno == EINTR)
            goto retry_write;

        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            if (parent) {
                parent->usock_pfds[usockp->usock_child_index].events = POLLOUT;
                return 0;
            }
        }
        usockp->usock_tx_buf = NULL;
    }

    return ret;
}

static void
usock_netlink_write_responses(struct vr_usocket *usockp)
{
    int ret;
    struct vr_message *resp;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(), usockp->usock_fd);
    while ((resp =
                (struct vr_message *)vr_queue_dequeue(&usockp->usock_nl_responses))) {
        usockp->usock_tx_buf = (unsigned char *)dpdk_nl_message_hdr(resp);
        usockp->usock_write_len = dpdk_nl_message_len(resp);
        usockp->usock_write_offset = 0;
        ret = __usock_write(usockp);
        if ((ret < 0) || (ret == usockp->usock_write_len)) {
            vr_message_free(resp);
        } else {
            break;
        }
    }

    return;
}


static int
usock_mbuf_write(struct vr_usocket *usockp, struct rte_mbuf *mbuf)
{
    unsigned int i, pkt_len;
    struct msghdr mhdr;
    struct rte_mbuf *m;
    struct iovec *iov;

    if (!mbuf)
        return 0;

    pkt_len = rte_pktmbuf_pkt_len(mbuf);
    if (!pkt_len)
        return 0;

    iov = usockp->usock_iovec;

    m = mbuf;
    for (i = 0; (m && (i < PKT0_MAX_IOV_LEN)); i++) {
        iov->iov_base = rte_pktmbuf_mtod(m, unsigned char *);
        iov->iov_len = rte_pktmbuf_data_len(m);
        m = m->pkt.next;
        iov++;
    }

    if ((i == PKT0_MAX_IOV_LEN) && m)
        usockp->usock_pkt_truncated++;

    mhdr.msg_name = NULL;
    mhdr.msg_namelen = 0;
    mhdr.msg_iov = usockp->usock_iovec;
    mhdr.msg_iovlen = i;
    mhdr.msg_control = NULL;
    mhdr.msg_controllen = 0;
    mhdr.msg_flags = 0;

#ifdef VR_DPDK_USOCK_DUMP
    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d sending message\n", __func__,
            pthread_self(), usockp->usock_fd);
    rte_hexdump(stdout, "usock message dump:", &mhdr, sizeof(mhdr));
#endif
    return sendmsg(usockp->usock_fd, &mhdr, MSG_DONTWAIT);
}

static void
vr_dpdk_pkt0_receive(struct vr_usocket *usockp)
{
    struct rte_pktmbuf *pmbuf;
    struct vr_packet *pkt;
    const unsigned lcore_id = rte_lcore_id();
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_interface_stats *stats;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                usockp->usock_fd);
    if (usockp->usock_vif) {
        pmbuf = &usockp->usock_mbuf->pkt;
        pmbuf->data = usockp->usock_rx_buf;
        pmbuf->data_len = usockp->usock_read_len;
        pmbuf->pkt_len = usockp->usock_read_len;
        /* convert mbuf to vr_packet */
        pkt = vr_dpdk_packet_get(usockp->usock_mbuf, usockp->usock_vif);
        /* send the packet to vRouter */
        vr_dpdk_packets_vroute(usockp->usock_vif, &pkt, 1);
        /* flush pkt0 TX queues immediately */
        vr_dpdk_lcore_flush(lcore);

        stats = vif_get_stats(usockp->usock_vif, lcore_id);
        stats->vis_deqpackets++;

        rcu_quiescent_state();
    } else {
        RTE_LOG(ERR, VROUTER, "Error receiving from packet socket: no vif attached\n");
        vr_dpdk_pfree(usockp->usock_mbuf, VP_DROP_INTERFACE_DROP);
    }

    usockp->usock_mbuf = NULL;
    usockp->usock_rx_buf = NULL;
    usockp->usock_buf_len = 0;

    return;
}

static void
vr_dpdk_drain_pkt0_ring(struct vr_usocket *usockp)
{
    int i;
    unsigned nb_pkts;
    struct rte_mbuf *mbuf_arr[VR_DPDK_RING_RX_BURST_SZ];

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: draining pkt0 ring...\n", __func__,
            pthread_self());
    do {
        nb_pkts = rte_ring_sc_dequeue_burst(vr_dpdk.packet_ring,
            (void **)&mbuf_arr, VR_DPDK_RING_RX_BURST_SZ);
        for (i = 0; i < nb_pkts; i++) {
            usock_mbuf_write(usockp->usock_parent, mbuf_arr[i]);
            rte_pktmbuf_free(mbuf_arr[i]);
        }
    } while (nb_pkts > 0);
}

static int
usock_read_done(struct vr_usocket *usockp)
{
    if (usockp->usock_state == READING_FAULTY_DATA)
        return 0;

    switch (usockp->usock_proto) {
    case PACKET:
        vr_dpdk_pkt0_receive(usockp);
        break;

    case EVENT:
        vr_dpdk_drain_pkt0_ring(usockp);
        break;

    case NETLINK:
        dpdk_netlink_receive(usockp, usockp->usock_rx_buf,
                usockp->usock_read_len);
        break;

    default:
        break;
    }

    return 0;
}

static int
usock_read_init(struct vr_usocket *usockp)
{
    usockp->usock_read_offset = 0;

    switch (usockp->usock_proto) {
    case NETLINK:
        if (usockp->usock_parent) {
            usockp->usock_read_len = NLMSG_HDRLEN;
            usockp->usock_state = READING_HEADER;
        }
        break;

    case EVENT:
        usockp->usock_read_len = USOCK_EVENT_BUF_LEN;
        usockp->usock_state = READING_DATA;
        break;

    case PACKET:
        if (usockp->usock_mbuf) {
            RTE_LOG(ERR, VROUTER, "Error initing usock read: mbuf is already exist\n");
            return -EINVAL;
        }

        usockp->usock_mbuf = rte_pktmbuf_alloc(usockp->usock_mbuf_pool);
        if (!usockp->usock_mbuf) {
            RTE_LOG(ERR, VROUTER, "Error initing usock read: cannot allocate mbuf\n");
            return -ENOMEM;
        }

        usockp->usock_rx_buf = rte_pktmbuf_mtod(usockp->usock_mbuf,
                char *);
        usockp->usock_buf_len = PKT0_MBUF_PACKET_SIZE;
        usockp->usock_read_len = PKT0_MBUF_PACKET_SIZE;
        usockp->usock_state = READING_DATA;
        break;

    default:
        break;
    }

    return 0;
}

static int
__usock_read(struct vr_usocket *usockp)
{
    int ret;
    unsigned int offset = usockp->usock_read_offset;
    unsigned int len = usockp->usock_read_len;
    unsigned int toread = len - offset;

    struct nlmsghdr *nlh;
    unsigned int proto = usockp->usock_proto;
    char *buf = usockp->usock_rx_buf;

    if (toread > usockp->usock_buf_len) {
        toread = usockp->usock_buf_len - offset;
    }

retry_read:
    ret = read(usockp->usock_fd, buf + offset, toread);
#ifdef VR_DPDK_USOCK_DUMP
    if (ret > 0) {
        RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d read %d bytes\n", __func__,
            pthread_self(), usockp->usock_fd, ret);
        rte_hexdump(stdout, "usock buffer dump:", buf + offset, ret);
    } else if (ret < 0) {
        RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d read returned error %d: %s (%d)\n", __func__,
            pthread_self(), usockp->usock_fd, ret, strerror(errno), errno);
    }
#endif
    if (ret <= 0) {
        if (!ret)
            return -1;

        if (errno == EINTR)
            goto retry_read;

        if ((errno == EAGAIN) ||
                (errno == EWOULDBLOCK))
            return 0;

        RTE_LOG(ERR, USOCK, "Error reading FD %d: %s (%d)\n",
                usockp->usock_fd, strerror(errno), errno);
        return ret;
    }

    offset += ret;
    usockp->usock_read_offset = offset;

    if (proto == NETLINK) {
        if (usockp->usock_state == READING_HEADER) {
            if (usockp->usock_read_offset == usockp->usock_read_len) {
                usockp->usock_state = READING_DATA;
                nlh = (struct nlmsghdr *)(usockp->usock_rx_buf);
                usockp->usock_read_len = nlh->nlmsg_len;
            }
        }

        if (usockp->usock_buf_len < usockp->usock_read_len) {
            usockp->usock_rx_buf = vr_malloc(usockp->usock_read_len);
            if (!usockp->usock_rx_buf) {
                /* bad, but let's recover */
                usockp->usock_rx_buf = buf;
                usockp->usock_read_len -= usockp->usock_read_offset;
                usockp->usock_read_offset = 0;
                usockp->usock_state = READING_FAULTY_DATA;
            } else {
                memcpy(usockp->usock_rx_buf, buf, usockp->usock_read_offset);
                vr_free(buf);
                usockp->usock_buf_len = usockp->usock_read_len;
                buf = usockp->usock_rx_buf;
            }
        }
    } else if (proto == PACKET) {
        usockp->usock_read_len = ret;
    }

    return ret;
}


static struct vr_usocket *
usock_alloc(unsigned short proto, unsigned short type)
{
    int sock_fd = -1, domain;
    int error = 0, flags;
    unsigned int buf_len;
    struct vr_usocket *usockp = NULL, *child;
    bool is_socket = true;
    unsigned short sock_type;

    RTE_SET_USED(child);

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: proto %u type %u\n", __func__,
                pthread_self(), proto, type);
    switch (type) {
    case TCP:
        domain = AF_INET;
        sock_type = SOCK_STREAM;
        break;

    case UNIX:
    case RAW:
        domain = AF_UNIX;
        sock_type = SOCK_DGRAM;
        break;

    default:
        return NULL;
    }

    if (proto == EVENT) {
        is_socket = false;
        sock_fd = eventfd(0, 0);
        RTE_LOG(DEBUG, USOCK, "%s[%lx]: new event FD %d\n", __func__,
                pthread_self(), sock_fd);
        if (sock_fd < 0)
            return NULL;
    }

    if (is_socket) {
        sock_fd = socket(domain, sock_type, 0);
        RTE_LOG(DEBUG, USOCK, "%s[%lx]: new socket FD %d\n", __func__,
                pthread_self(), sock_fd);
        if (sock_fd < 0)
            return NULL;
    }

    usockp = vr_zalloc(sizeof(*usockp));
    if (!usockp)
        goto error_exit;

    usockp->usock_type = type;
    usockp->usock_proto = proto;
    usockp->usock_fd = sock_fd;
    usockp->usock_state = INITED;

    if (is_socket) {
        error = vr_usocket_bind(usockp);
        if (error < 0)
            goto error_exit;

        if (usockp->usock_proto == PACKET) {
            error = vr_usocket_connect(usockp);
            if (error < 0)
                goto error_exit;
        }
    }

    switch (proto) {
    case NETLINK:
        usockp->usock_max_cfds = USOCK_MAX_CHILD_FDS;
        buf_len = 0;
        break;

    case PACKET:
        usockp->usock_max_cfds = USOCK_MAX_CHILD_FDS;
        buf_len = 0;
        break;

    case EVENT:
        buf_len = USOCK_EVENT_BUF_LEN;
        break;

    default:
        buf_len = 0;
        break;
    }

    if (buf_len) {
        usockp->usock_rx_buf = vr_zalloc(buf_len);
        if (!usockp->usock_rx_buf)
            goto error_exit;

        usockp->usock_buf_len = buf_len;
        usock_read_init(usockp);
    }

    if (proto == PACKET) {
        usockp->usock_mbuf_pool = rte_mempool_lookup("pkt0_mbuf_pool");
        if (!usockp->usock_mbuf_pool) {
            usockp->usock_mbuf_pool = rte_mempool_create("pkt0_mbuf_pool",
                    PKT0_MBUF_POOL_SIZE, PKT0_MBUF_PACKET_SIZE,
                    PKT0_MBUF_POOL_CACHE_SZ, sizeof(struct rte_pktmbuf_pool_private),
                    rte_pktmbuf_pool_init, NULL, vr_dpdk_pktmbuf_init, NULL,
                    rte_socket_id(), 0);
            if (!usockp->usock_mbuf_pool)
                goto error_exit;
        }

        usockp->usock_iovec = vr_zalloc(sizeof(struct iovec) *
                PKT0_MAX_IOV_LEN);
        if (!usockp->usock_iovec)
            goto error_exit;

        usock_read_init(usockp);
    }

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d F_GETFL\n", __func__, pthread_self(),
                usockp->usock_fd);
    flags = fcntl(usockp->usock_fd, F_GETFL);
    if (flags == -1)
        goto error_exit;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d F_SETFL\n", __func__, pthread_self(),
                usockp->usock_fd);
    error = fcntl(usockp->usock_fd, F_SETFL, flags | O_NONBLOCK);
    if (error == -1)
        goto error_exit;

    usockp->usock_poll_block = 1;

    return usockp;

error_exit:

    error = errno;
    if (sock_fd >= 0) {
        close(sock_fd);
        sock_fd = -1;
    }

    usock_close(usockp);
    usockp = NULL;
    errno = error;

    return usockp;
}

/*
 * currently defined protocols are netlink and packet.
 * for packet, only raw socket type is accepted
 * for netlink, both tcp and unix socket types are accepted
 */
static bool
valid_usock(int proto, int type)
{
    RTE_LOG(DEBUG, USOCK, "%s[%lx]: proto %u type %u\n", __func__,
            pthread_self(), proto, type);
    if ((proto != PACKET) &&
            (proto != NETLINK) &&
            (proto != EVENT))
        return -EINVAL;

    if (((proto == PACKET) || (proto == EVENT)) && (type != RAW)) {
        return -EINVAL;
    } else {
        if (type != TCP && type != UNIX)
            return -EINVAL;
    }

    return true;
}

void
vr_usocket_detach_vif(void *usockp)
{
    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                        ((struct vr_usocket *)usockp)->usock_fd);
    ((struct vr_usocket *)usockp)->usock_vif = NULL;
    return;
}

void
vr_usocket_attach_vif(void *usockp, struct vr_interface *vif)
{
    if (!vif)
        return;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                        ((struct vr_usocket *)usockp)->usock_fd);
    ((struct vr_usocket *)usockp)->usock_vif = vif;
    return;
}

void
vr_usocket_non_blocking(struct vr_usocket *usockp)
{
    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                usockp->usock_fd);
    usockp->usock_poll_block = 0;
    return;
}

int
vr_usocket_write(struct vr_usocket *usockp, unsigned char *buf,
        unsigned int len)
{
    if (usockp->usock_tx_buf)
        return -1;

    usockp->usock_tx_buf = buf;
    usockp->usock_write_offset = 0;
    usockp->usock_write_len = len;

    return __usock_write(usockp);
}

int
vr_usocket_message_write(struct vr_usocket *usockp,
        struct vr_message *message)
{
    int ret;
    unsigned int len;
    unsigned char *buf;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                usockp->usock_fd);
    if ((usockp->usock_proto != NETLINK) && (usockp->usock_type != TCP))
        return -EINVAL;

    if (usockp->usock_tx_buf || !vr_queue_empty(&usockp->usock_nl_responses)) {
        vr_queue_enqueue(&usockp->usock_nl_responses,
                &message->vr_message_queue);
        return 0;
    }

    buf = (unsigned char *)dpdk_nl_message_hdr(message);
    len = dpdk_nl_message_len(message);
    ret = vr_usocket_write(usockp, buf, len);
    if (ret == len) {
        vr_message_free(message);
    }

    return ret;
}

static int
vr_usocket_read(struct vr_usocket *usockp)
{
    int ret;

    if (!usockp || usockp->usock_fd < 0)
        return -1;

    switch (usockp->usock_state) {
    case LISTENING:
    case LIMITED:
        ret = vr_usocket_accept(usockp);
        if (ret < 0)
            return ret;

        break;

    case READING_HEADER:
    case READING_DATA:
    case READING_FAULTY_DATA:
        ret = __usock_read(usockp);
        if (ret < 0) {
            RTE_LOG(DEBUG, USOCK, "%s[%lx]: read error FD %d\n", __func__, pthread_self(),
                        usockp->usock_fd);
            usock_close(usockp);
            return ret;
        }

        if (usockp->usock_read_offset == usockp->usock_read_len) {
            usock_read_done(usockp);
            /* we have the complete message */
            usock_read_init(usockp);
        }

        break;

    default:
        return -1;
    }

    return ret;
}

static int
vr_usocket_connect(struct vr_usocket *usockp)
{
    struct sockaddr_un sun;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                usockp->usock_fd);
    if (usockp->usock_proto != PACKET)
        return -EINVAL;

    sun.sun_family = AF_UNIX;
    memset(sun.sun_path, 0, sizeof(sun.sun_path));
    strncpy(sun.sun_path, VR_PACKET_AGENT_UNIX_FILE, sizeof(sun.sun_path) - 1);

#ifdef VR_DPDK_USOCK_DUMP
    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d retry connecting\n", __func__,
            pthread_self(), usockp->usock_fd);
    rte_hexdump(stdout, "usock address dump:", &sun, sizeof(sun));
#endif
    return vr_dpdk_retry_connect(usockp->usock_fd, (struct sockaddr *)&sun,
                                        sizeof(sun));
}

static int
vr_usocket_accept(struct vr_usocket *usockp)
{
    int ret;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                usockp->usock_fd);
    ret = accept(usockp->usock_fd, NULL, NULL);
    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d accepted %d\n", __func__, pthread_self(),
                    usockp->usock_fd, ret);
    if (ret < 0) {
        usock_set_error(usockp, ret);
        return ret;
    }

    if ((usockp->usock_state == LIMITED) ||
            (usock_clone(usockp, ret)))
        close(ret);

    return 0;
}

static int
vr_usocket_bind(struct vr_usocket *usockp)
{
    int error = 0;
    struct sockaddr_in sin;
    struct sockaddr_un sun;
    struct sockaddr *addr = NULL;
    socklen_t addrlen = 0;
    int optval;
    bool server;

    optval = 1;
    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d setting option\n", __func__,
            pthread_self(), usockp->usock_fd);
    if (setsockopt(usockp->usock_fd, SOL_SOCKET, SO_REUSEADDR, &optval,
                sizeof(optval)))
        return -errno;

    switch (usockp->usock_type) {
    case TCP:
        sin.sin_family = AF_INET;
        sin.sin_port = htons(VR_NETLINK_TCP_PORT);
        sin.sin_addr.s_addr = INADDR_ANY;
        addr = (struct sockaddr *)&sin;
        addrlen = sizeof(sin);
        server = true;

        break;

    case UNIX:
        sun.sun_family = AF_UNIX;
        memset(sun.sun_path, 0, sizeof(sun.sun_path));
        strncpy(sun.sun_path, VR_NETLINK_UNIX_FILE, sizeof(sun.sun_path) - 1);
        addr = (struct sockaddr *)&sun;
        addrlen = sizeof(sun);
        server = true;
        mkdir(VR_SOCKET_DIR, VR_SOCKET_DIR_MODE);
        unlink(sun.sun_path);

        break;

    case RAW:
        sun.sun_family = AF_UNIX;
        memset(sun.sun_path, 0, sizeof(sun.sun_path));
        strncpy(sun.sun_path, VR_PACKET_UNIX_FILE, sizeof(sun.sun_path) - 1);
        addr = (struct sockaddr *)&sun;
        addrlen = sizeof(sun);
        server = false;
        mkdir(VR_SOCKET_DIR, VR_SOCKET_DIR_MODE);
        unlink(sun.sun_path);

        break;

    default:
        return -EINVAL;
    }

#ifdef VR_DPDK_USOCK_DUMP
    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d binding\n", __func__, pthread_self(),
            usockp->usock_fd);
    rte_hexdump(stdout, "usock address dump:", addr, addrlen);
#endif
    error = bind(usockp->usock_fd, addr, addrlen);
    if (error < 0)
        return error;

    if (server) {
        RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d listening\n", __func__,
                pthread_self(),  usockp->usock_fd);
        error = listen(usockp->usock_fd, 1);
        if (error < 0)
            return error;
        usockp->usock_state = LISTENING;
    }

    return 0;
}

void
vr_usocket_close(void *sock)
{
    struct vr_usocket *usockp = (struct vr_usocket *)sock;

    if (usockp == NULL)
        return;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                usockp->usock_fd);
    if (usockp->usock_io_in_progress) {
        usockp->usock_should_close = 1;
        return;
    }

    usock_close(usockp);
    return;
}

/*
 * create a usocket which is of type (TCP/UNIX/RAW). the messages
 * read in those sockets will follow protocol 'proto'. protocol is
 * netlink, packet or event
 */
void *
vr_usocket(int proto, int type)
{
    struct vr_usocket *usockp = NULL;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: proto %u type %u\n", __func__,
                pthread_self(), proto, type);
    RTE_SET_USED(usockp);

    if (!valid_usock(proto, type))
        return NULL;

    return (void *)usock_alloc(proto, type);
}

static int
usock_write(struct vr_usocket *usockp)
{
    int ret;

    if (!usockp || usockp->usock_fd < 0)
        return 0;

    ret = __usock_write(usockp);
    if (ret < 0) {
        usock_close(usockp);
        return ret;
    }

    if (usockp->usock_proto == NETLINK) {
        if (usockp->usock_write_offset == usockp->usock_write_len) {
            usock_netlink_write_responses(usockp);
        }
    }

    return 0;
}


/*
 * start io on socket
 */
int
vr_usocket_io(void *transport)
{
    int ret, i, processed;
    int timeout;
    struct pollfd *pfd;
    struct vr_usocket *usockp = (struct vr_usocket *)transport;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[rte_lcore_id()];
    unsigned lcore_id = rte_lcore_id();
    unsigned master_lcore_id = rte_get_master_lcore();

    if (!usockp)
        return -1;

    RTE_LOG(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                usockp->usock_fd);
    if ((ret = usock_init_poll(usockp)))
        goto return_from_io;

    pfd = &usockp->usock_pfds[0];
    pfd->fd = usockp->usock_fd;
    pfd->events = POLLIN;

    usockp->usock_io_in_progress = 1;

    timeout = usockp->usock_poll_block ? INFINITE_TIMEOUT : 0;
    while (1) {
        if (usockp->usock_should_close) {
            usock_close(usockp);
            return -1;
        }

        rcu_thread_offline();

        /* TODO: handle an IPC command only for pkt0 thread
         * and just check the stop flag for the rest
         */
        if (unlikely(vr_dpdk_lcore_cmd_handle(lcore)))
            break;

        ret = poll(usockp->usock_pfds, usockp->usock_max_cfds,
                timeout);

        /* manage timers on pkt0 lcore */
        if (lcore_id == vr_dpdk.packet_lcore_id
            && lcore_id != master_lcore_id)
            rte_timer_manage();

        if (ret < 0) {
            usock_set_error(usockp, ret);
            /* all other errors are fatal */
            if (errno != EINTR)
                goto return_from_io;
        }

        processed = 0;
        pfd = usockp->usock_pfds;
        for (i = 0; (i < usockp->usock_max_cfds) && (processed < ret);
                i++, pfd++) {
            if ((pfd->fd >= 0)) {
                if (pfd->revents & POLLIN) {
                    if (i == 0) {
                        ret = vr_usocket_read(usockp);
                        if (ret < 0)
                            return ret;
                    } else {
                        vr_usocket_read(usockp->usock_children[i]);
                    }
                }

                if (pfd->revents & POLLOUT) {
                    usock_write(usockp->usock_children[i]);
                }

                if (pfd->revents & POLLHUP) {
                    if (i) {
                        usock_close(usockp->usock_children[i]);
                    } else {
                        break;
                    }
                }

                if (pfd->revents)
                    processed++;
            }
        }

        if (!timeout)
            return 0;
    }

return_from_io:
    usockp->usock_io_in_progress = 0;
    usock_deinit_poll(usockp);

    return ret;
}
