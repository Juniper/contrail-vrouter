/*
 * Copyright (C) 2014 Semihalf.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * vr_netlink.c -- NetLink functions
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <signal.h>

#include "vr_types.h"
#include "vr_os.h"
#include "vr_message.h"
#include "vr_genetlink.h"
#include "vr_dpdk.h"

#define DPDK_NL_HDR_LEN        (NLMSG_HDRLEN + GENL_HDRLEN + sizeof(struct nlattr))
#define DPDK_VROUTER_PIDFILE    "/tmp/vrouter.pid"

/* Handle NetLink messages */
int
vr_dpdk_netlink_handle(void)
{
    struct sockaddr_nl sock_addr;
    struct vr_message request, *resp;
    struct nlmsghdr *nlh;
    struct nlattr *nla;
    uint8_t *message_buf = &vr_dpdk.netlink_buf[0];
    unsigned int multi_flag;
    __u32 seq;
    int socklen = sizeof(sock_addr);
    int ret = 0;
    int sock = vr_dpdk.netlink_sock;

    if (sock < 0)
        return -EBADF;

    memset(&sock_addr, 0, socklen);
    /* check if there are new messages in the socket */
    ret = recvfrom(sock, message_buf, VR_DPDK_NL_BUF_SZ, 0,
        (struct sockaddr *)&sock_addr, &socklen);
    if (ret <= 0) {
        /* interrupted system call is OK (Ctrl+C or kill) */
        if (errno == EINTR) {
            return 0;
        }

        RTE_LOG(ERR, VROUTER, "%s: Can't read from socket %d: %s\n",
            __func__, sock, strerror(errno));
        return errno;
    }
#ifdef VR_DPDK_NETLINK_PKT_DUMP
    rte_hexdump("Got NetLink Message:", message_buf, ret);
#endif

    nlh = (struct nlmsghdr *)message_buf;
    seq = nlh->nlmsg_seq;
    request.vr_message_buf = message_buf + DPDK_NL_HDR_LEN;
    request.vr_message_len = ret - DPDK_NL_HDR_LEN;
    vr_message_request(&request);

    /* Process responses */
    multi_flag = 0;
    while ((resp = vr_message_dequeue_response())) {
        if (!multi_flag && !vr_response_queue_empty())
            multi_flag = NLM_F_MULTI;

        /*
         * Copy response payload after request header,
         * so it can be reused
         */
        rte_memcpy(&message_buf[DPDK_NL_HDR_LEN], resp->vr_message_buf,
            resp->vr_message_len);
        resp->vr_message_len = RTE_ALIGN(resp->vr_message_len, 4);

        /* Update Netlink headers */
        nlh = (struct nlmsghdr *)message_buf;
        nlh->nlmsg_len = resp->vr_message_len + DPDK_NL_HDR_LEN;
        nlh->nlmsg_flags = multi_flag;
        nlh->nlmsg_seq = seq;
        nlh->nlmsg_pid = 0;

        nla = (struct nlattr *)(message_buf + NLMSG_HDRLEN + GENL_HDRLEN);
        nla->nla_len = resp->vr_message_len;
        nla->nla_type = NL_ATTR_VR_MESSAGE_PROTOCOL;

#ifdef VR_DPDK_NETLINK_PKT_DUMP
        rte_hexdump("Sending NetLink Response:", message_buf, resp->vr_message_len
            + DPDK_NL_HDR_LEN);
#endif

        ret = sendto(sock, message_buf,    resp->vr_message_len + DPDK_NL_HDR_LEN, 0,
            (struct sockaddr *)&sock_addr, sizeof(sock_addr));
        if (ret <= 0) {
            RTE_LOG(ERR, VROUTER, "%s: Cannot read from socket %d: %s\n",
                __func__, sock, strerror(errno));
            vr_message_free(resp);
            return ret;
        }

        vr_message_free(resp);
    }

    if (multi_flag) {
        nlh = (struct nlmsghdr *)message_buf;
        nlh->nlmsg_len = NLMSG_HDRLEN;
        nlh->nlmsg_type = NLMSG_DONE;
        nlh->nlmsg_flags = 0;
        nlh->nlmsg_seq = seq;
        nlh->nlmsg_pid = 0;
#ifdef VR_DPDK_NETLINK_PKT_DUMP
        rte_hexdump("Response Message:", message_buf, NLMSG_HDRLEN);
#endif

        ret = sendto(sock, nlh, NLMSG_HDRLEN, 0,
            (struct sockaddr *)&sock_addr, sizeof(sock_addr));
        if (ret <= 0) {
            RTE_LOG(ERR, VROUTER, "%s: Cannot read from socket %d: %s\n",
                __func__, sock, strerror(errno));
            return errno;
        }
    }

    return ret;
}

static int
dpdk_router_save_pid(void)
{
    FILE *pid_file;

    pid_file = fopen(DPDK_VROUTER_PIDFILE, "w");
    if (!pid_file) {
            RTE_LOG(ERR, VROUTER, "%s: cannot open pidfile: %s\n", __func__,
                strerror(errno));
        return errno;
    }

    fprintf(pid_file,"%u", getpid());
    fclose(pid_file);

    return 0;
}

/* Close NetLink socket */
void
vr_dpdk_netlink_sock_close(void)
{
    if (vr_dpdk.netlink_sock >= 0)
        close(vr_dpdk.netlink_sock);
}

/* Init NetLink socket */
int
vr_dpdk_netlink_sock_init(void)
{
    struct sockaddr_nl sock_addr;
    int sock;
    int ret = 0;

    ret = dpdk_router_save_pid();
    if (ret)
        return ret;

    sock = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_GENERIC);
    if (sock < 0)
        return sock;

    bzero(&sock_addr, sizeof(sock_addr));
    sock_addr.nl_family = AF_NETLINK;
    sock_addr.nl_pid = getpid();

    ret = bind(sock, (const struct sockaddr *)&sock_addr, sizeof(sock_addr));
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "%s: bind error: %s\n", __func__, strerror(errno));
        close(sock);
        return ret;
    }

    /* save socket handler */
    vr_dpdk.netlink_sock = sock;
    return 0;
}
