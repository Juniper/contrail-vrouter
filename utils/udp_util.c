/*
 * udp_util.c -- netlink utility functions common for all the utilities
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#include <sys/socket.h>
#if defined(__linux__)
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/sockios.h>

#include <stdint.h>
#include <net/if.h>
#include <netinet/in.h>
#elif defined(__FreeBSD__)
#include <net/if.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#endif

#include "udp_util.h"

#include "host/vr_host.h"
#include "host/vr_host_interface.h"

uint8_t *
udp_get_buf_ptr(struct udp_client *cl)
{
    return (uint8_t *)(cl->cl_buf + cl->cl_buf_offset);
}

uint32_t
udp_get_buf_len(struct udp_client *cl)
{
    return cl->cl_buf_len - cl->cl_buf_offset;
}

struct udp_response *
udp_parse_reply(struct udp_client *cl)
{
    struct udp_response *resp = &cl->cl_resp;

    resp->udp_data = (uint8_t *)cl->cl_buf;
    resp->udp_len = cl->cl_recv_len;

    return resp;
}

void
udp_free(struct udp_client *cl)
{
    if (cl->cl_sock >= 0) {
        close(cl->cl_sock);
        cl->cl_sock = -1;
    }

    if (cl->cl_buf)
        free(cl->cl_buf);

    cl->cl_buf = NULL;
    cl->cl_buf_offset = 0;
    cl->cl_buf_len = 0;

    return;
}

void
udp_update_len(struct udp_client *cl, unsigned int len)
{
    cl->cl_buf_offset += len;
    return;
}

int
udp_socket(struct udp_client *cl, uint16_t port)
{
    struct sockaddr_in sa;

    if (cl->cl_sock >= 0)
        return -EEXIST;

    cl->cl_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (cl->cl_sock < 0)
        return cl->cl_sock;

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (connect(cl->cl_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        return -errno;

    return cl->cl_sock;
}

int
udp_recvmsg(struct udp_client *cl)
{
    int ret;
    struct sockaddr_in sa;
    struct msghdr msg;
    struct iovec iov;

    memset(&msg, 0, sizeof(msg));
    memset(&sa, 0, sizeof(sa));

    sa.sin_family = AF_INET;
    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);

    iov.iov_base = (void *)(cl->cl_buf);
    iov.iov_len = cl->cl_buf_len;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    cl->cl_buf_offset = 0;

    ret = recvmsg(cl->cl_sock, &msg, MSG_DONTWAIT);
    if (ret < 0) {
        return ret;
    }

    cl->cl_recv_len = ret;
    if (cl->cl_recv_len > cl->cl_buf_len)
        return -EOPNOTSUPP;

    return ret;
}

int
udp_sendmsg(struct udp_client *cl)
{
    struct msghdr msg;
    struct iovec iov;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = (void *)(cl->cl_buf);
    iov.iov_len = cl->cl_buf_offset;

    cl->cl_buf_offset = 0;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    return sendmsg(cl->cl_sock, &msg, 0);
}

struct udp_client *
udp_register_client(void)
{
    struct udp_client *cl;

    cl = calloc(sizeof(*cl), 1);
    if (!cl)
        return cl;

    cl->cl_buf = calloc(UDP_MSG_DEFAULT_SIZE, 1);
    if (!cl->cl_buf)
        goto exit_register;
    cl->cl_buf_len = UDP_MSG_DEFAULT_SIZE;
    cl->cl_sock = -1;

    return cl;
exit_register:
    if (cl)
        udp_free_client(cl);

    return NULL;
}

void
udp_free_client(struct udp_client *cl)
{
    udp_free(cl);
    free(cl);

    return;
}

#define MIN(a, b) ((int)a < (int)b ? a : b)

int
uvr_nametotype(const char *name)
{
    unsigned int len;

    len = strlen(name);
    if (!strncmp(name, "pkt", MIN(len, strlen("pkt")))) {
        return UDP_IFTYPE_AGENT;
    }
    if (!strncmp(name, "eth", MIN(len, strlen("eth")))) {
        return UDP_IFTYPE_PHYSICAL;
    }
    if (!strncmp(name, "tap", MIN(len, strlen("tap")))) {
        return UDP_IFTYPE_VIRTUAL;
    }

    return -1;
}

int
uvr_nametoindex(const char *name)
{
    unsigned int len;
    unsigned int ifnum;

    errno = 0;

    len = strlen(name);
    if (!strncmp(name, "pkt", MIN(len, strlen("pkt"))))
        return HIF_AGENT_INTERFACE_INDEX;
    if (!strncmp(name, "eth", MIN(len, strlen("eth")))) {
        ifnum = strtoul(&name[3], NULL, 0);
        if (errno)
            return -1;
        return HIF_PHYSICAL_INTERFACE_INDEX + ifnum;
    }

    if (!strncmp(name, "tap", MIN(len, strlen("tap")))) {
        ifnum = strtoul(&name[3], NULL, 0);
        if (errno)
            return -1;
        return (HIF_VIRTUAL_INTERFACE_INDEX_START + (ifnum % HIF_NUM_VIRTUAL_INTERFACES));
    }

    return -1;
}

