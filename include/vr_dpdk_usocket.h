/*
 * vr_dpdk_usocket.h -- user space io helpers
 *
 * Copyright (c) 2014, Juniper Networks, Inc.
 * All rights reserved
 */
#ifndef __VR_DPDK_USOCKET_H__
#define __VR_DPDK_USOCKET_H__

#include "vr_queue.h"
#include "nl_util.h"
#include <pthread.h>

/*
 * usocket is an object where io happens. while it can represent non
 * socket objects too (like an eventfd), most consumers are socket
 * users and hence usocket is primarily a socket.
 *
 * A socket, when used for io, has to have a protocol to understand
 * the format of the data that enters and exits it. We have three
 * protocols: NETLINK, PACKET and EVENT.
 *
 * A NETLINK socket carries netlink messages i.e.: each message in the
 * socket will be headed by a netlink header.
 *
 * A PACKET socket carries packets that are headed with agent_hdr. A
 * PACKET socket is actually a link between the datapath threads and
 * the agent. The datapath threads enqueue packets that are to be sent
 * to the agent on a ring and wakeup the packet thread. The packet
 * thread dequeues the packet from the ring and sends the packet to
 * the connection with the agent. When a new packet arrives from the
 * agent, the packet thread wakes up and enqueues it to the vrouter.
 * So, a PACKET socket has a ring, a vif, and a child usocket that
 * represents an eventfd that is written by the datapath threads to
 * wake up the packet thread whenever there are new packets that are
 * enqueued on the ring.
 *
 * The EVENT protocol represent and eventfd. You can write an 8 byte
 * value that will be accumulated over writes to be read by the reader.
 *
 * For each of the protocol, multiple transport types could make sense.
 * For e.g.: for a NETLINK socket, both a TCP and a UNIX transport could
 * make sense. However, for a packet socket, only a RAW transport will
 * make sense.
 */

/* protocol type */
#define NETLINK                 1
#define PACKET                  2
#define EVENT                   3

/* socket type */
#define TCP                     1
#define UNIX                    2
#define RAW                     3

/* usocket state */
#define ALLOCED                 0
#define INITED                  1
#define LISTENING               2
#define READING_HEADER          3
#define READING_DATA            4
#define READING_FAULTY_DATA     5
#define LIMITED                 6

#define USOCK_MAX_CHILD_FDS     64
#define USOCK_RX_BUF_LEN        4096
#define USOCK_EVENT_BUF_LEN     sizeof(uint64_t)

#define PKT0_MBUF_POOL_SIZE     8192
#define PKT0_MBUF_POOL_CACHE_SZ (VR_DPDK_RX_BURST_SZ*8)
#define PKT0_MBUF_PACKET_SIZE   2048
#define PKT0_MAX_IOV_LEN        64
#define PKT0_MBUF_RING_SIZE     65536

struct vr_usocket {
    unsigned short usock_type;
    unsigned short usock_proto;
    short usock_poll_block;
    unsigned short usock_io_in_progress;
    unsigned short usock_should_close;

    int usock_fd;
    unsigned int usock_state;

    int usock_error;
    int usock_errno;

    int usock_cfds;
    int usock_child_index;

    unsigned int usock_max_cfds;
    unsigned int usock_disconnects;

    struct vr_usocket *usock_parent;
    struct vr_usocket **usock_children;

    unsigned int usock_read_offset;
    unsigned int usock_read_len;

    unsigned int usock_buf_len;
    unsigned int usock_pkt_truncated;

    char *usock_rx_buf;

    struct rte_mbuf *usock_mbuf;
    struct rte_mempool *usock_mbuf_pool;

    unsigned int usock_write_offset;
    unsigned int usock_write_len;
    unsigned char *usock_tx_buf;
    struct vr_qhead usock_nl_responses;

    struct iovec *usock_iovec;

    struct vr_interface *usock_vif;
    struct pollfd *usock_pfds;
    pthread_t usock_owner;
};

void *vr_usocket(int, int);
void vr_usocket_close(void *sock);
/*
 * start io on socket
 */
int vr_usocket_io(void *transport);
void vr_usocket_non_blocking(struct vr_usocket *usockp);
void vr_usocket_attach_vif(void *usockp, struct vr_interface *vif);
int vr_usocket_bind_usockets(void *usock1, void *usock2);
int vr_usocket_write(struct vr_usocket *usockp, unsigned char *buf,
    unsigned int len);
int vr_usocket_eventfd_write(struct vr_usocket *usockp);

#define VR_DEF_SOCKET_DIR_MODE      (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)
#define VR_NETLINK_UNIX_NAME        "dpdk_netlink"
#define VR_PACKET_UNIX_NAME         "dpdk_pkt0"
#define VR_PACKET_AGENT_UNIX_NAME   "agent_pkt0"

#endif /* __VR_DPDK_USOCKET_H__ */
