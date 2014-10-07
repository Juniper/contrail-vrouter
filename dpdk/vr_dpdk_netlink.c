/*
 * vr_dpdk_netlink.c -- message handling from agent
 *
 * Copyright (c) 2014, Juniper Networks Private Inc.,
 * All rights reserved
 */
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

#include <linux/netlink.h>
#include <linux/genetlink.h>

#include "vr_queue.h"
#include "vr_dpdk_usocket.h"
#include "vr_message.h"
#include "vr_dpdk.h"
#include "vr_genetlink.h"

#define HDR_LEN (NLMSG_HDRLEN + GENL_HDRLEN + sizeof(struct nlattr))

struct nlmsghdr *dpdk_nl_message_hdr(struct vr_message *);
unsigned int dpdk_nl_message_len(struct vr_message *);

int vr_usocket_message_write(struct vr_usocket *, struct vr_message *);

static void
dpdk_nl_process_response(void *usockp, struct nlmsghdr *nlh)
{
    __u32 seq;
    unsigned int multi_flag = 0;
    bool write = true;

    struct vr_message *resp;

    struct nlmsghdr *resp_nlh;
    struct genlmsghdr *genlh, *resp_genlh;
    struct nlattr *resp_nla;

    seq = nlh->nlmsg_seq;
    genlh = (struct genlmsghdr *)((unsigned char *)nlh + NLMSG_HDRLEN);

    /* Process responses */
    while ((resp = (struct vr_message *)vr_message_dequeue_response())) {
        if (!write) {
            vr_message_free(resp);
            continue;
        }

        if (!vr_response_queue_empty()) {
            multi_flag = NLM_F_MULTI;
        } else {
            multi_flag = NLMSG_DONE;
        }

        resp->vr_message_len = RTE_ALIGN(resp->vr_message_len, 4);

        /* Update Netlink headers */
        resp_nlh = dpdk_nl_message_hdr(resp);
        resp_nlh->nlmsg_len = dpdk_nl_message_len(resp);
        resp_nlh->nlmsg_type = nlh->nlmsg_type;
        resp_nlh->nlmsg_flags = multi_flag;
        resp_nlh->nlmsg_seq = seq;
        resp_nlh->nlmsg_pid = 0;

        resp_genlh = (struct genlmsghdr *)((unsigned char *)resp_nlh + 
                NLMSG_HDRLEN);
        memcpy(resp_genlh, genlh, sizeof(*genlh));

        resp_nla = (struct nlattr *)((unsigned char *)resp_genlh + GENL_HDRLEN);
        resp_nla->nla_len = resp->vr_message_len;
        resp_nla->nla_type = NL_ATTR_VR_MESSAGE_PROTOCOL;

        if (vr_usocket_message_write(usockp, resp) < 0) {
            write = false;
            vr_usocket_close(usockp);
        }
    }

    return;
}

int
dpdk_netlink_receive(void *usockp, char *nl_buf,
        unsigned int nl_len)
{
    struct vr_message request;

    request.vr_message_buf = nl_buf + HDR_LEN;
    request.vr_message_len = nl_len - HDR_LEN;
    vr_message_request(&request);

    dpdk_nl_process_response(usockp, (struct nlmsghdr *)nl_buf);

    return 0;
}

unsigned int
dpdk_nl_message_len(struct vr_message *message)
{
    return message->vr_message_len + HDR_LEN;
}

struct nlmsghdr *
dpdk_nl_message_hdr(struct vr_message *message)
{
    return (struct nlmsghdr *)(message->vr_message_buf - HDR_LEN);
}

static void
dpdk_nl_trans_free(char *buf)
{
    buf -= HDR_LEN;
    vr_free(buf);

    return;
}

static char *
dpdk_nl_trans_alloc(unsigned int size)
{
    char *buf;

    buf = vr_malloc(size + HDR_LEN);
    if (!buf)
        return NULL;

    return buf + HDR_LEN;
}

static struct vr_mtransport dpdk_nl_transport = {
    .mtrans_alloc       =       dpdk_nl_trans_alloc,
    .mtrans_free        =       dpdk_nl_trans_free,
};

int
dpdk_netlink_io(void)
{
    return vr_usocket_io(vr_dpdk.netlink_sock);
}

void
dpdk_netlink_exit(void)
{
    vr_message_transport_unregister(&dpdk_nl_transport);
    vr_usocket_close(vr_dpdk.netlink_sock);

    return;
}

int
dpdk_netlink_init(void)
{
    int ret;
    int num_cores = rte_lcore_count();

    ret = vr_message_transport_register(&dpdk_nl_transport);
    if (ret)
        return ret;

    vr_dpdk.netlink_sock = vr_usocket(NETLINK, TCP);
    if (!vr_dpdk.netlink_sock) {
        RTE_LOG(ERR, VROUTER, "Failed to create the NETLINK server socket\n");
        return -1;
    }

    if (num_cores == VR_DPDK_MIN_LCORES)
        vr_usocket_non_blocking(vr_dpdk.netlink_sock);

    return 0;
}
