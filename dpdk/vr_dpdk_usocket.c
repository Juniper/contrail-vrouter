/*
 * vr_dpdk_usocket.c -- library to deal with packet0 and netlink tcp/unix
 * sockets
 *
 * Copyright(c) 2014, Juniper Networks Inc.
 * All rights reserved
 */

#include <fcntl.h>
#include <poll.h>
#include <linux/netlink.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <stdint.h>
#include <netinet/tcp.h>

#include "nl_util.h"
#include "vr_dpdk.h"
#include "vr_dpdk_usocket.h"
#include "vr_message.h"

#include <rte_byteorder.h>
#include <rte_errno.h>
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

static char vr_packet_unix_file[VR_UNIX_PATH_MAX];
char *vr_socket_dir = VR_DEF_SOCKET_DIR;
uint16_t vr_netlink_port = VR_DEF_NETLINK_PORT;

/*
 * mark the error in socket for somebody to process/see
 */
static void
usock_set_error(struct vr_usocket *usockp, int error)
{
    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d error %d\n", __func__, pthread_self(),
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

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(), usockp->usock_fd);
    if (usockp->usock_pfds) {
        vr_free(usockp->usock_pfds, VR_USOCK_POLL_OBJECT);
        usockp->usock_pfds = NULL;
    }

    return;
}

/*
 * for both netlink and packet protocol sockets, we will need to poll. in case
 * of netlink, the poll in on tcp sockets to accept a connection (from agent,
 * utilities etc.:). for packet socket, the poll is on unix socket to receive
 * packets from agent and to be passed to vrouter. packet sockets also will
 * have an event usocket to dequeue packets from the packet_mbuf_ring, where
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

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(), usockp->usock_fd);
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
                usockp->usock_max_cfds + 1, VR_USOCK_POLL_OBJECT);
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

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: parent FD %d child FD %d\n", __func__,
            pthread_self(), parent->usock_fd, child->usock_fd);

    if (child->usock_proto == EVENT) {
        child_pair = vr_usocket(EVENT, RAW);
        if (!child_pair)
            return -ENOMEM;

        RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: parent FD %d closing child FD %d\n",
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
                USOCK_MAX_CHILD_FDS + 1, VR_USOCK_OBJECT);
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

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: usock1 FD %d usock2 FD %d\n", __func__,
            pthread_self(), parent->usock_fd, child->usock_fd);
    return usock_bind_usockets(parent, child);
}

static int
usock_clone(struct vr_usocket *parent, int cfd)
{
    struct vr_usocket *child;

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: parent FD %d cfd %d\n", __func__,
            pthread_self(), parent->usock_fd, cfd);
    child = vr_zalloc(sizeof(struct vr_usocket), VR_USOCK_OBJECT);
    if (!child) {
        usock_set_error(parent, -ENOMEM);
        goto error_return;
    }

    child->usock_rx_buf = vr_malloc(USOCK_RX_BUF_LEN, VR_USOCK_BUF_OBJECT);
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
            vr_free(child->usock_rx_buf, VR_USOCK_BUF_OBJECT);
        vr_free(child, VR_USOCK_OBJECT);
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
    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: child FD %d parent %p\n", __func__,
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

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(), usockp->usock_fd);
    usock_unbind(usockp);
    usock_deinit_poll(usockp);

    for (i = 0; i < usockp->usock_cfds; i++) {
        usock_close(usockp->usock_children[i]);
    }

    RTE_LOG_DP(DEBUG, USOCK, "%s: closing FD %d\n", __func__, usockp->usock_fd);
    close(usockp->usock_fd);

    if (!usockp->usock_mbuf_pool && usockp->usock_rx_buf) {
        vr_free(usockp->usock_rx_buf, VR_USOCK_BUF_OBJECT);
        usockp->usock_rx_buf = NULL;
    }

    if (usockp->usock_iovec) {
        vr_free(usockp->usock_iovec, VR_USOCK_IOVEC_OBJECT);
        usockp->usock_iovec = NULL;
    }

    if (usockp->usock_mbuf_pool) {
        /* no api to destroy a pool */
    }

    if (usockp->usock_proto == PACKET) {
        RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: unlinking %s\n", __func__,
            pthread_self(), vr_packet_unix_file);
        unlink(vr_packet_unix_file);
    }

    usockp->usock_io_in_progress = 0;

    vr_free(usockp, VR_USOCK_OBJECT);

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
    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d writing %d bytes\n",
                __func__, pthread_self(), usockp->usock_fd, len);
    rte_hexdump(stdout, "usock buffer dump:", buf, len);
#endif
    if (usockp->usock_owner != pthread_self()) {
        if (usockp->usock_owner)
            RTE_LOG(WARNING, USOCK, "WARNING: thread %lx (lcore %u) is trying to write %u bytes"
                " to usocket FD %d owned by thread %lx\n",
                pthread_self(), rte_lcore_id(), len, usockp->usock_fd, usockp->usock_owner);
        usockp->usock_owner = pthread_self();
    }
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
        RTE_LOG_DP(DEBUG, VROUTER, "%s[%lx]: write error FD %d\n", __func__, pthread_self(),
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

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(), usockp->usock_fd);
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
        m = m->next;
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
    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d sending message\n", __func__,
            pthread_self(), usockp->usock_fd);
    rte_hexdump(stdout, "usock message dump:", &mhdr, sizeof(mhdr));
#endif
    return sendmsg(usockp->usock_fd, &mhdr, MSG_DONTWAIT);
}

static void
vr_dpdk_packet_receive(struct vr_usocket *usockp)
{
    const unsigned lcore_id = rte_lcore_id();
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_interface_stats *stats;

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                usockp->usock_fd);
    /**
     * Packets is read from the agent's socket here. On success, a counter for
     * packets dequeued from the interface is incremented.
     */
    stats = vif_get_stats(usockp->usock_vif, lcore_id);
    if (usockp->usock_vif) {
        stats->vis_port_ipackets++;
        /* buf_addr and data_off do not change */
        usockp->usock_mbuf->data_len = usockp->usock_read_len;
        usockp->usock_mbuf->pkt_len = usockp->usock_read_len;
        /* convert mbuf to vr_packet */
        vr_dpdk_packet_get(usockp->usock_mbuf, usockp->usock_vif);
        /* send the mbuf to vRouter */
        vr_dpdk_lcore_vroute(lcore, usockp->usock_vif, &usockp->usock_mbuf, 1);
        /* flush packet TX queues immediately */
        vr_dpdk_lcore_flush(lcore);
    } else {
        /**
         * If reading from socket failed, increment counter for interface
         * dequeue drops.
         */
        RTE_LOG(ERR, VROUTER, "Error receiving from packet socket: no vif attached\n");
        vr_dpdk_pfree(usockp->usock_mbuf, NULL, VP_DROP_INTERFACE_DROP);
        stats->vis_port_ierrors++;
    }

    usockp->usock_mbuf = NULL;
    usockp->usock_rx_buf = NULL;
    usockp->usock_buf_len = 0;

    return;
}

static void
vr_dpdk_packet_ring_drain(struct vr_usocket *usockp)
{
    int i;
    unsigned nb_pkts;
    struct rte_mbuf *mbuf_arr[VR_DPDK_RX_BURST_SZ];
    const unsigned lcore_id = rte_lcore_id();
    struct vr_interface_stats *stats;

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: draining packet ring...\n", __func__,
            pthread_self());

    if (unlikely(usockp->usock_parent->usock_vif == NULL))
        return;

    rcu_thread_offline();

    stats = vif_get_stats(usockp->usock_parent->usock_vif, lcore_id);
    do {
        nb_pkts = rte_ring_sc_dequeue_burst(vr_dpdk.packet_ring,
            (void **)&mbuf_arr, VR_DPDK_RX_BURST_SZ);
        for (i = 0; i < nb_pkts; i++) {
            if (usock_mbuf_write(usockp->usock_parent, mbuf_arr[i]) >= 0)
                stats->vis_port_opackets++;
            else {
                stats->vis_port_oerrors++;
                RTE_LOG_DP(DEBUG, USOCK,
                        "%s: Error writing mbuf to packet socket: %s (%d)\n",
                        __func__, rte_strerror(errno), errno);
            }

            rte_pktmbuf_free(mbuf_arr[i]);
        }
    } while (nb_pkts > 0);

    rcu_thread_online();
}

static int
usock_read_done(struct vr_usocket *usockp)
{
    if (usockp->usock_state == READING_FAULTY_DATA)
        return 0;

    switch (usockp->usock_proto) {
    case PACKET:
        vr_dpdk_packet_receive(usockp);
        break;

    case EVENT:
        vr_dpdk_packet_ring_drain(usockp);
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

        usockp->usock_rx_buf = rte_pktmbuf_mtod(usockp->usock_mbuf, char *);
        usockp->usock_buf_len = usockp->usock_mbuf->buf_len
                                - rte_pktmbuf_headroom(usockp->usock_mbuf);
        usockp->usock_read_len = usockp->usock_buf_len;
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
    if (usockp->usock_owner != pthread_self()) {
        if (usockp->usock_owner)
            RTE_LOG(WARNING, USOCK, "WARNING: thread %lx is trying to read"
                " usocket FD %d owned by thread %lx\n",
                pthread_self(), usockp->usock_fd, usockp->usock_owner);
        usockp->usock_owner = pthread_self();
    }
    ret = read(usockp->usock_fd, buf + offset, toread);
#ifdef VR_DPDK_USOCK_DUMP
    if (ret > 0) {
        RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d read %d bytes\n", __func__,
            pthread_self(), usockp->usock_fd, ret);
        rte_hexdump(stdout, "usock buffer dump:", buf + offset, ret);
    } else if (ret < 0) {
        RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d read returned error %d: %s (%d)\n", __func__,
            pthread_self(), usockp->usock_fd, ret, rte_strerror(errno), errno);
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
                usockp->usock_fd, rte_strerror(errno), errno);
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
            usockp->usock_rx_buf = vr_malloc(usockp->usock_read_len,
                    VR_USOCK_BUF_OBJECT);
            if (!usockp->usock_rx_buf) {
                /* bad, but let's recover */
                usockp->usock_rx_buf = buf;
                usockp->usock_read_len -= usockp->usock_read_offset;
                usockp->usock_read_offset = 0;
                usockp->usock_state = READING_FAULTY_DATA;
            } else {
                memcpy(usockp->usock_rx_buf, buf, usockp->usock_read_offset);
                vr_free(buf, VR_USOCK_BUF_OBJECT);
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
    int sock_fd = -1, domain, ret;
    /* socket TX buffer size = (hold flow table entries * size of jumbo frame) */
    int setsocksndbuff = vr_flow_hold_limit * vr_packet_sz;
    int getsocksndbuff;
    socklen_t getsocksndbufflen = sizeof(getsocksndbuff);
    int error = 0, flags;
    unsigned int buf_len;
    struct vr_usocket *usockp = NULL, *child;
    bool is_socket = true;
    unsigned short sock_type;
    int flag = 1;

    RTE_SET_USED(child);

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: proto %u type %u\n", __func__,
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
        RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: new event FD %d\n", __func__,
                pthread_self(), sock_fd);
        if (sock_fd < 0)
            return NULL;
    }

    if (is_socket) {
        sock_fd = socket(domain, sock_type, 0);
        RTE_LOG(INFO, USOCK, "%s[%lx]: new socket FD %d\n", __func__,
                pthread_self(), sock_fd);
        if (sock_fd < 0)
            return NULL;

        if (type == TCP) {
            RTE_LOG(INFO, USOCK, "%s[%lx]: setting socket FD %d nodelay.\n"
                        , __func__, pthread_self(), sock_fd);
            ret = setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag,
                             sizeof(int));
            if (ret != 0) {
                RTE_LOG(ERR, USOCK, "%s[%lx]: setting socket FD %d nodelay failed (%d).\n"
                        , __func__, pthread_self(), sock_fd, errno);
            }
        }

        /* set socket send buffer size */
        ret = setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &setsocksndbuff,
                         sizeof(setsocksndbuff));
        if (ret == 0) {
            /* check if setting buffer succeeded */
            ret = getsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &getsocksndbuff,
                             &getsocksndbufflen);
            if (ret == 0) {
                if (getsocksndbuff >= setsocksndbuff) {
                    RTE_LOG(INFO, USOCK, "%s[%lx]: setting socket FD %d send buff size.\n"
                            "Buffer size set to %d (requested %d)\n", __func__,
                            pthread_self(), sock_fd, getsocksndbuff, setsocksndbuff);
                } else { /* set other than requested */
                    RTE_LOG(ERR, USOCK, "%s[%lx]: setting socket FD %d send buff size failed.\n"
                            "Buffer size set to %d (requested %d)\n", __func__,
                            pthread_self(), sock_fd, getsocksndbuff, setsocksndbuff);
                }
            } else { /* requesting buffer size failed */
                RTE_LOG(ERR, USOCK, "%s[%lx]: getting socket FD %d send buff size failed (%d)\n",
                         __func__, pthread_self(), sock_fd, errno);
            }
        } else { /* setting buffer size failed */
            RTE_LOG(ERR, USOCK, "%s[%lx]: setting socket FD %d send buff size %d failed (%d)\n",
                     __func__, pthread_self(), sock_fd, setsocksndbuff, errno);
        }
    }

    usockp = vr_zalloc(sizeof(*usockp), VR_USOCK_OBJECT);
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
        /* TODO: we don't need the buf since we use stack to send an event */
        buf_len = USOCK_EVENT_BUF_LEN;
        break;

    default:
        buf_len = 0;
        break;
    }

    if (buf_len) {
        usockp->usock_rx_buf = vr_zalloc(buf_len, VR_USOCK_BUF_OBJECT);
        if (!usockp->usock_rx_buf)
            goto error_exit;

        usockp->usock_buf_len = buf_len;
        usock_read_init(usockp);
    }

    if (proto == PACKET) {
        usockp->usock_mbuf_pool = rte_mempool_lookup("packet_mbuf_pool");
        if (!usockp->usock_mbuf_pool) {
            usockp->usock_mbuf_pool = rte_mempool_create("packet_mbuf_pool",
                    PKT0_MBUF_POOL_SIZE, PKT0_MBUF_PACKET_SIZE,
                    PKT0_MBUF_POOL_CACHE_SZ, sizeof(struct rte_pktmbuf_pool_private),
                    vr_dpdk_pktmbuf_pool_init, NULL, vr_dpdk_pktmbuf_init, NULL,
                    rte_socket_id(), 0);
            if (!usockp->usock_mbuf_pool)
                goto error_exit;
        }

        usockp->usock_iovec = vr_zalloc(sizeof(struct iovec) *
                PKT0_MAX_IOV_LEN, VR_USOCK_IOVEC_OBJECT);
        if (!usockp->usock_iovec)
            goto error_exit;

        usock_read_init(usockp);
    }

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d F_GETFL\n", __func__, pthread_self(),
                usockp->usock_fd);
    flags = fcntl(usockp->usock_fd, F_GETFL);
    if (flags == -1)
        goto error_exit;

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d F_SETFL\n", __func__, pthread_self(),
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
    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: proto %u type %u\n", __func__,
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
    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                        ((struct vr_usocket *)usockp)->usock_fd);
    ((struct vr_usocket *)usockp)->usock_vif = NULL;
    return;
}

void
vr_usocket_attach_vif(void *usockp, struct vr_interface *vif)
{
    if (!vif)
        return;

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                        ((struct vr_usocket *)usockp)->usock_fd);
    ((struct vr_usocket *)usockp)->usock_vif = vif;
    return;
}

void
vr_usocket_non_blocking(struct vr_usocket *usockp)
{
    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
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
vr_usocket_eventfd_write(struct vr_usocket *usockp)
{
    if (usockp->usock_proto != EVENT)
        return -1;

    return eventfd_write(usockp->usock_fd, 1);
}

int
vr_usocket_message_write(struct vr_usocket *usockp,
        struct vr_message *message)
{
    int ret;
    unsigned int len;
    unsigned char *buf;

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
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
            RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: read error FD %d\n", __func__, pthread_self(),
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

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                usockp->usock_fd);
    if (usockp->usock_proto != PACKET)
        return -EINVAL;

    sun.sun_family = AF_UNIX;
    memset(sun.sun_path, 0, sizeof(sun.sun_path));
    strncpy(sun.sun_path, vr_socket_dir, sizeof(sun.sun_path) - 1);
    strncat(sun.sun_path, "/"VR_PACKET_AGENT_UNIX_NAME, sizeof(sun.sun_path)
        - strlen(sun.sun_path) - 1);

#ifdef VR_DPDK_USOCK_DUMP
    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d retry connecting\n", __func__,
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

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
                usockp->usock_fd);
    ret = accept(usockp->usock_fd, NULL, NULL);
    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d accepted %d\n", __func__, pthread_self(),
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
    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d setting option\n", __func__,
            pthread_self(), usockp->usock_fd);
    if (setsockopt(usockp->usock_fd, SOL_SOCKET, SO_REUSEADDR, &optval,
                sizeof(optval)))
        return -errno;

    switch (usockp->usock_type) {
    case TCP:
        sin.sin_family = AF_INET;
        sin.sin_port = rte_cpu_to_be_16(vr_netlink_port);
        sin.sin_addr.s_addr = INADDR_ANY;
        addr = (struct sockaddr *)&sin;
        addrlen = sizeof(sin);
        server = true;

        break;

    case UNIX:
        sun.sun_family = AF_UNIX;
        memset(sun.sun_path, 0, sizeof(sun.sun_path));
        strncpy(sun.sun_path, vr_socket_dir, sizeof(sun.sun_path) - 1);
        strncat(sun.sun_path, "/"VR_NETLINK_UNIX_NAME, sizeof(sun.sun_path)
            - strlen(sun.sun_path) - 1);

        addr = (struct sockaddr *)&sun;
        addrlen = sizeof(sun);
        server = true;
        mkdir(vr_socket_dir, VR_DEF_SOCKET_DIR_MODE);
        unlink(sun.sun_path);

        break;

    case RAW:
        sun.sun_family = AF_UNIX;
        memset(sun.sun_path, 0, sizeof(sun.sun_path));
        strncpy(vr_packet_unix_file, vr_socket_dir, sizeof(vr_packet_unix_file)
            - 1);
        strncat(vr_packet_unix_file, "/"VR_PACKET_UNIX_NAME,
            sizeof(vr_packet_unix_file) - strlen(vr_packet_unix_file) - 1);
        strncpy(sun.sun_path, vr_packet_unix_file, sizeof(sun.sun_path) - 1);

        addr = (struct sockaddr *)&sun;
        addrlen = sizeof(sun);
        server = false;
        mkdir(vr_socket_dir, VR_DEF_SOCKET_DIR_MODE);
        unlink(sun.sun_path);

        break;

    default:
        return -EINVAL;
    }

#ifdef VR_DPDK_USOCK_DUMP
    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d binding\n", __func__, pthread_self(),
            usockp->usock_fd);
    rte_hexdump(stdout, "usock address dump:", addr, addrlen);
#endif
    error = bind(usockp->usock_fd, addr, addrlen);
    if (error < 0)
        return error;

    if (server) {
        RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d listening\n", __func__,
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

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
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
    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: proto %u type %u\n", __func__,
                pthread_self(), proto, type);

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
    unsigned lcore_id = rte_lcore_id();
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];

    if (!usockp)
        return -1;

    RTE_LOG_DP(DEBUG, USOCK, "%s[%lx]: FD %d\n", __func__, pthread_self(),
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

        /*
         * Handle an IPC commands for IO_LCORE_ID up
         * and just check the stop flag for the rest.
         */
        if (lcore_id >= VR_DPDK_IO_LCORE_ID) {
            if (unlikely(vr_dpdk_lcore_cmd_handle(lcore)))
                break;
        } else {
            if (unlikely(vr_dpdk_is_stop_flag_set()))
                break;
        }

        rcu_thread_offline();
        ret = poll(usockp->usock_pfds, usockp->usock_max_cfds,
                timeout);
        if (ret < 0) {
            usock_set_error(usockp, ret);
            /* all other errors are fatal */
            if (errno != EINTR)
                goto return_from_io;
        }

        rcu_thread_online();

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

