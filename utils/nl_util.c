/*
 * nl_util.c -- netlink utility functions common for all the utilities
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#if defined(__linux__)
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/sockios.h>
#include <linux/dcbnl.h>
#endif

#include <stdint.h>
#include <net/if.h>
#include <netinet/in.h>
#include "vr_types.h"
#include "nl_util.h"
#include "vr_genetlink.h"
#include "vr_os.h"

#define VROUTER_GENETLINK_FAMILY_NAME "vrouter"
#define GENL_ID_VROUTER         (NLMSG_MIN_TYPE + 0x10)

extern struct nl_response *nl_parse_gen(struct nl_client *);

extern void vrouter_ops_process (void *a) __attribute__((weak));
extern void vr_flow_req_process(void *s_req) __attribute__((weak));
extern void vr_flow_response_process(void *s_req) __attribute__((weak));
extern void vr_route_req_process(void *s_req) __attribute__((weak));
extern void vr_interface_req_process(void *s_req) __attribute__((weak));
extern void vr_mpls_req_process(void *s_req) __attribute__((weak));
extern void vr_mirror_req_process(void *s_req) __attribute__((weak));
extern void vr_response_process(void *s_req) __attribute__((weak));
extern void vr_nexthop_req_process(void *s_req) __attribute__((weak));
extern void vr_vrf_assign_req_process(void *s_req) __attribute__((weak));
extern void vr_vrf_stats_req_process(void *s_req) __attribute__((weak));
extern void vr_drop_stats_req_process(void *s_req) __attribute__((weak));
extern void vr_vxlan_req_process(void *s_req) __attribute__((weak));
extern void vr_mem_stats_req_process(void *s_req) __attribute__((weak));
extern void vr_fc_map_req_process(void *s_req) __attribute__((weak));
extern void vr_qos_map_req_process(void *s_req) __attribute__((weak));
extern void vr_flow_table_data_process(void *s_req) __attribute__((weak));

void
vrouter_ops_process(void *s_req)
{
    return;
}

void
vr_nexthop_req_process(void *s_req)
{
    return;
}


void
vr_flow_req_process(void *s_req)
{
    return;
}

void
vr_flow_response_process(void *s__req)
{
    return;
}

void
vr_flow_table_data_process(void *s__req)
{
    return;
}

void
vr_route_req_process(void *s_req)
{
    return;
}

void
vr_interface_req_process(void *s_req)
{
    return;
}

void
vr_mpls_req_process(void *s_req)
{
    return;
}

void
vr_mirror_req_process(void *s_req)
{
    return;
}

void
vr_response_process(void *s_req)
{
    return;
}


void
vr_vrf_assign_req_process(void *s_req)
{
    return;
}

void
vr_vrf_stats_req_process(void *s_req)
{
    return;
}

void
vr_drop_stats_req_process(void *s_req)
{
    return;
}

void
vr_vxlan_req_process(void *s_req)
{
    return;
}

void
vr_mem_stats_req_process(void *s_req)
{
    return;
}

void
vr_qos_map_req_process(void *s_req)
{
    return;
}

void
vr_fc_map_req_process(void *s_req)
{
    return;
}

struct nl_response *
nl_parse_gen_ctrl(struct nl_client *cl)
{
    int len;
    struct nlattr *nla;
    struct genl_ctrl_message *msg;
    char *buf = cl->cl_buf + cl->cl_buf_offset;
    struct nl_response *resp = &cl->resp;

    msg = (struct genl_ctrl_message *)cl->cl_resp_buf;
    resp->nl_data = (uint8_t *)(msg);
    memset(msg, 0, sizeof(*msg));
    msg->family_id = -1;

    len = cl->cl_msg_len - (cl->cl_buf_offset - cl->cl_msg_start);
    nla = (struct nlattr *)buf;

    while (len > 0 && len > NLA_HDRLEN) {
        if (len < NLA_ALIGN(nla->nla_len))
            return nl_set_resp_err(cl, -EINVAL);

        switch (nla->nla_type) {
        case CTRL_ATTR_FAMILY_NAME:
            strncpy(msg->family_name, NLA_DATA(nla), sizeof(msg->family_name) - 1);
            break;

        case CTRL_ATTR_FAMILY_ID:
            msg->family_id = *(unsigned short *)NLA_DATA(nla);
            break;

        default:
            break;
        }

        cl->cl_buf_offset += NLA_ALIGN(nla->nla_len);
        len -= NLA_ALIGN(nla->nla_len);
        nla = (struct nlattr *)((char *)nla + NLA_ALIGN(nla->nla_len));
    }

    return resp;
}


struct nl_response *
nl_parse_gen(struct nl_client *cl)
{
    char *buf = cl->cl_buf + cl->cl_buf_offset;
    struct genlmsghdr *ghdr;
    struct nl_response *resp = &cl->resp;
    struct nlattr *nla;

    if (cl->cl_buf_len < cl->cl_buf_offset + GENL_HDRLEN)
        return nl_set_resp_err(cl, -EINVAL);

    ghdr = (struct genlmsghdr *)buf;
    cl->cl_buf_offset += GENL_HDRLEN;

    resp->nl_op = ghdr->cmd;
    if (resp->nl_type == NL_MSG_TYPE_GEN_CTRL) {
        return nl_parse_gen_ctrl(cl);
    } else {
        nla = (struct nlattr *)(cl->cl_buf + cl->cl_buf_offset);
        resp->nl_len = nla->nla_len;
        cl->cl_buf_offset += NLA_HDRLEN;
        resp->nl_data = (uint8_t *)(cl->cl_buf + cl->cl_buf_offset);
        return resp;
    }
}

static int
nl_build_sandesh_attr_without_attr_len(struct nl_client *cl)
{
    struct nlattr *nla = (struct nlattr *)
        ((char *)cl->cl_buf + cl->cl_buf_offset);

    if (cl->cl_buf_offset + NLA_HDRLEN > cl->cl_buf_len)
        return -ENOMEM;

    nla->nla_len = NLA_HDRLEN;
    nla->nla_type = NL_ATTR_VR_MESSAGE_PROTOCOL;
    cl->cl_buf_offset += NLA_HDRLEN;

    return 0;
}

int
nl_build_header(struct nl_client *cl, unsigned char **buf, uint32_t *buf_len)
{
    int ret;

    if (!cl->cl_buf)
        return -EINVAL;

    if (!cl->cl_genl_family_id)
        return -EINVAL;

    ret = nl_build_nlh(cl, cl->cl_genl_family_id, NLM_F_REQUEST);
    if (ret)
        return ret;

    ret = nl_build_genlh(cl, SANDESH_REQUEST, 0);
    if (ret)
        return ret;

    ret = nl_build_sandesh_attr_without_attr_len(cl);
    if (ret)
        return ret;

    *buf = (unsigned char *)(cl->cl_buf) + cl->cl_buf_offset;
    *buf_len = cl->cl_buf_len - cl->cl_buf_offset;

    return 0;
}

void
nl_update_header(struct nl_client *cl, int data_len)
{
    /* First update attribute header len for NLA_SANDESH_ATTR */
    struct nlattr *nla = (struct nlattr *)
        ((char *)cl->cl_buf + cl->cl_buf_offset - NLA_HDRLEN);

    assert(nla->nla_type == NL_ATTR_VR_MESSAGE_PROTOCOL);
    nla->nla_len +=  data_len;

    cl->cl_buf_offset += data_len;
    nl_update_nlh(cl);
}

int
nl_family_name_attr_length(char *family)
{
    return NLA_HDRLEN + NLA_ALIGN(strlen(family) + 1);
}

int
nl_build_family_name_attr(struct nl_client *cl, char *family)
{
    char *buf;
    int len;
    struct nlattr *nla = (struct nlattr *)
        ((char *)cl->cl_buf + cl->cl_buf_offset);

    len = nl_family_name_attr_length(family);
    if (cl->cl_buf_offset + len > cl->cl_buf_len)
        return -ENOMEM;

    nla->nla_len = len;
    nla->nla_type = CTRL_ATTR_FAMILY_NAME;
    cl->cl_buf_offset += NLA_HDRLEN;

    buf = (char *)cl->cl_buf + cl->cl_buf_offset;
    strcpy(buf, family);
    cl->cl_buf_offset += NLA_ALIGN(strlen(family) + 1);

    return 0;
}


int
nl_build_get_family_id(struct nl_client *cl, char *family)
{
    int ret;

    if (!cl->cl_buf)
        return -ENOMEM;

    ret = nl_build_nlh(cl, GENL_ID_CTRL, NLM_F_REQUEST);
    if (ret)
        return ret;

    ret = nl_build_genlh(cl, CTRL_CMD_GETFAMILY, 0);
    if (ret)
        return ret;

    ret = nl_build_family_name_attr(cl, family);
    if (ret)
        return ret;

    nl_update_nlh(cl);

    return 0;
}

int
nl_build_genlh(struct nl_client *cl, uint8_t cmd, uint8_t version)
{
    struct genlmsghdr *genlh = (struct genlmsghdr *)
        ((char *)cl->cl_buf + cl->cl_buf_offset);

    if (cl->cl_buf_offset + GENL_HDRLEN > cl->cl_buf_len)
        return -ENOMEM;

    genlh->cmd = cmd;
    genlh->version = version;
    genlh->reserved = 0;

    cl->cl_buf_offset += GENL_HDRLEN;

    return 0;
}


struct nl_response *
nl_set_resp_err(struct nl_client *cl, int error)
{
    struct nl_response *resp = (struct nl_response *)cl->cl_resp_buf;

    resp->nl_type = NL_MSG_TYPE_ERROR;
    resp->nl_op = error;
    return resp;
}


void
nl_update_nlh(struct nl_client *cl)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)cl->cl_buf;

    nlh->nlmsg_len = cl->cl_msg_len = cl->cl_buf_offset;

    return;
}

int
nl_get_attr_hdr_size()
{
    return NLA_HDRLEN;
}

uint8_t *
nl_get_buf_ptr(struct nl_client *cl)
{
    return (uint8_t *)(cl->cl_buf + cl->cl_buf_offset);
}

uint32_t
nl_get_buf_len(struct nl_client *cl)
{
    return cl->cl_buf_len - cl->cl_buf_offset;
}

void
nl_update_attr_len(struct nl_client *cl, int len)
{
    struct nlattr *nla;

    nla = (struct nlattr *)cl->cl_attr;
    nla->nla_len += len;
    cl->cl_buf_offset += len;
    return;
}

void
nl_build_attr(struct nl_client *cl, int len, int attr)
{
    struct nlattr *nla;

    nla = (struct nlattr *)(cl->cl_buf + cl->cl_buf_offset);
    cl->cl_attr = (uint8_t *)nla;
    nla->nla_len = NLA_HDRLEN + (len);
    nla->nla_type = attr;

    /* Adjust by attribute length */
    cl->cl_buf_offset += NLA_HDRLEN + (len);
}


int
nl_build_nlh(struct nl_client *cl, uint32_t type, uint32_t flags)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)(cl->cl_buf);

    if (cl->cl_buf_offset + NLMSG_HDRLEN > cl->cl_buf_len)
        return -ENOMEM;

    nlh->nlmsg_len = cl->cl_buf_len;
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_seq = cl->cl_seq++;
    nlh->nlmsg_pid = cl->cl_id;

    cl->cl_buf_offset = NLMSG_HDRLEN;

    return 0;
}

void
nl_free(struct nl_client *cl)
{
    if (cl->cl_sock >= 0) {
        close(cl->cl_sock);
        cl->cl_sock = -1;
    }

    if (cl->cl_buf)
        free(cl->cl_buf);

    if (cl->cl_resp_buf)
        free(cl->cl_resp_buf);

    if (cl->cl_sa)
        free(cl->cl_sa);

    cl->cl_buf = NULL;
    cl->cl_resp_buf = NULL;
    cl->cl_buf_offset = 0;
    cl->cl_buf_len = 0;
    cl->cl_resp_buf_len = 0;
    cl->cl_sa = NULL;
    cl->cl_sa_len = 0;
    cl->cl_recvmsg = NULL;

    return;
}

int
nl_socket(struct nl_client *cl, int domain, int type, int protocol)
{
    if (cl->cl_sock >= 0)
        return -EEXIST;

#if defined(__FreeBSD__)
    /*
     * Fake Contrail socket has only one protocol for handling
     * sandesh protocol, so zero must be passed as a parameter
     */
    domain = AF_VENDOR00;
    type = SOCK_DGRAM;
    protocol = 0;
#endif
    cl->cl_sock = socket(domain, type, protocol);
    if (cl->cl_sock < 0)
        return cl->cl_sock;

    cl->cl_sock_protocol = protocol;
    cl->cl_socket_domain = domain;
    cl->cl_socket_type = type;

    if (type == SOCK_STREAM) {
        cl->cl_recvmsg = nl_client_stream_recvmsg;
    } else {
        cl->cl_recvmsg = nl_client_datagram_recvmsg;
    }

    return cl->cl_sock;
}

int
nl_connect(struct nl_client *cl, uint32_t ip, uint16_t port)
{
    if (cl->cl_socket_domain == AF_NETLINK) {
        struct sockaddr_nl *sa = malloc(sizeof(struct sockaddr_nl));

        if (!sa)
            return -1;

        memset(sa, 0, sizeof(*sa));
        sa->nl_family = cl->cl_socket_domain;
        sa->nl_pid = cl->cl_id;
        cl->cl_sa = (struct sockaddr *)sa;
        cl->cl_sa_len = sizeof(*sa);

        return bind(cl->cl_sock, cl->cl_sa, cl->cl_sa_len);
    }

    if (cl->cl_socket_domain == AF_INET) {
        struct in_addr address;
        struct sockaddr_in *sa = malloc(sizeof(struct sockaddr_in));
        if (!sa)
            return -1;

        memset(sa, 0, sizeof(*sa));
        address.s_addr = htonl(ip);
        sa->sin_family = cl->cl_socket_domain;
        sa->sin_addr = address;
        sa->sin_port = htons(port);
        cl->cl_sa = (struct sockaddr *)sa;
        cl->cl_sa_len = sizeof(*sa);

        return connect(cl->cl_sock, cl->cl_sa, cl->cl_sa_len);
    }
    return 0;
}

int
nl_client_datagram_recvmsg(struct nl_client *cl)
{
    int ret;
    struct msghdr msg;
    struct iovec iov;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = cl->cl_sa;
    msg.msg_namelen = cl->cl_sa_len;

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
nl_client_stream_recvmsg(struct nl_client *cl) {
    int ret;
    struct msghdr msg;
    struct iovec iov;

    memset(&msg, 0, sizeof(msg));

    msg.msg_name = cl->cl_sa;
    msg.msg_namelen = sizeof(cl->cl_sa_len);

    iov.iov_base = (void *)(cl->cl_buf);
    iov.iov_len = NLMSG_HDRLEN;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    cl->cl_buf_offset = 0;

    /* read netlink header and get the lenght of sandesh message */
    ret = recvmsg(cl->cl_sock, &msg, 0);
    if (ret < 0) {
        return ret;
    }
    struct nlmsghdr *nlh = (struct nlmsghdr *)(cl->cl_buf + cl->cl_buf_offset);
    uint32_t pending_length = nlh->nlmsg_len - NLMSG_HDRLEN;

    /* read sandesh message */
    iov.iov_base = (void *)(cl->cl_buf + NLMSG_HDRLEN);
    iov.iov_len = pending_length;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    ret = recvmsg(cl->cl_sock, &msg, 0);
    if (ret < 0) {
        return ret;
    }

    cl->cl_recv_len = nlh->nlmsg_len;
    if (cl->cl_recv_len > cl->cl_buf_len)
        return -EOPNOTSUPP;

    return ret;
}

int
nl_recvmsg(struct nl_client *cl)
{
    return cl->cl_recvmsg(cl);
}

int
nl_sendmsg(struct nl_client *cl)
{
    struct msghdr msg;
    struct iovec iov;

    memset(&msg, 0, sizeof(msg));
#if defined (__linux__)
    msg.msg_name = cl->cl_sa;
    msg.msg_namelen = cl->cl_sa_len;
#endif

    iov.iov_base = (void *)(cl->cl_buf);
    iov.iov_len = cl->cl_buf_offset;

    cl->cl_buf_offset = 0;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    return sendmsg(cl->cl_sock, &msg, 0);
}

void
nl_set_buf(struct nl_client *cl, char *buf, unsigned int len)
{
    if (cl->cl_buf)
        free(cl->cl_buf);

    cl->cl_buf =  buf;
    cl->cl_buf_offset = 0;
    cl->cl_buf_len = len;
    cl->cl_msg_len = 0;

    return;
}

void
nl_set_rcv_len(struct nl_client *cl, unsigned int rcv_len)
{
    cl->cl_recv_len = rcv_len;
    cl->cl_buf_offset = 0;
    cl->cl_msg_len = 0;

    return;
}

void
nl_set_genl_family_id(struct nl_client *cl, unsigned int family_id)
{
    cl->cl_genl_family_id = family_id;

    return;
}

struct nl_client *
nl_register_client(void)
{
    struct nl_client *cl;

    cl = calloc(sizeof(*cl), 1);
    if (!cl)
        return cl;

    cl->cl_buf = calloc(NL_MSG_DEFAULT_SIZE, 1);
    if (!cl->cl_buf)
        goto exit_register;
    cl->cl_buf_len = NL_MSG_DEFAULT_SIZE;
    cl->cl_resp_buf = malloc(NL_RESP_DEFAULT_SIZE);
    if (!cl->cl_resp_buf)
        goto exit_register;
    cl->cl_resp_buf_len = NL_RESP_DEFAULT_SIZE;

    cl->cl_id = 0;
    cl->cl_sock = -1;

    return cl;

exit_register:
    if (cl)
        nl_free_client(cl);

    return NULL;
}

void
nl_free_client(struct nl_client *cl)
{
    nl_free(cl);
    free(cl);

    return;
}

int
nl_init_generic_client_req(struct nl_client *cl, int family)
{
    memset(cl, 0, sizeof(*cl));
    cl->cl_sock_protocol = NETLINK_GENERIC;
    cl->cl_buf = malloc(NL_MSG_DEFAULT_SIZE);
    if (!cl->cl_buf)
        goto exit_register;
    cl->cl_buf_len = NL_MSG_DEFAULT_SIZE;
    cl->cl_genl_family_id = family;
    cl->cl_sock = -1;
    return 1;

exit_register:
    return 0;
}


struct nl_response *
nl_parse_reply(struct nl_client *cl)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)(cl->cl_buf +
            cl->cl_buf_offset);
    struct nlmsgerr *err;
    struct nl_response *resp =  &cl->resp;

    memset(resp, 0, sizeof(*resp));
    resp->nl_type = NL_MSG_TYPE_ERROR;
    if (cl->cl_buf_offset + NLMSG_HDRLEN > cl->cl_recv_len)
        return NULL;

    cl->cl_msg_len = nlh->nlmsg_len;
    cl->cl_msg_start = cl->cl_buf_offset;
    if (cl->cl_msg_len + cl->cl_buf_offset  > cl->cl_recv_len)
        return nl_set_resp_err(cl, -ENOMEM);

    cl->cl_buf_offset += NLMSG_HDRLEN;

    if (nlh->nlmsg_type == NLMSG_DONE) {
        resp->nl_type = NL_MSG_TYPE_DONE;
        return resp;
    } else if (nlh->nlmsg_type == NETLINK_GENERIC) {
        resp->nl_type = NL_MSG_TYPE_GEN_CTRL;
        resp = nl_parse_gen(cl);
    } else if (nlh->nlmsg_type == cl->cl_genl_family_id) {
        resp->nl_type = NL_MSG_TYPE_FMLY;
        resp = nl_parse_gen(cl);
    } else if ((nlh->nlmsg_type == RTM_SETDCB) ||
            (nlh->nlmsg_type == RTM_GETDCB)) {
        resp->nl_type = nlh->nlmsg_type;
        resp->nl_data = nl_get_buf_ptr(cl);
    } else {
        err = (struct nlmsgerr *)nl_get_buf_ptr(cl);
        return nl_set_resp_err(cl, err->error);
    }
    return resp;
}

int
vrouter_get_family_id(struct nl_client *cl)
{
    int ret;
    struct nl_response *resp;
    struct genl_ctrl_message *msg;

#if defined(__linux__)
    if (cl->cl_socket_domain != AF_NETLINK) {
        nl_set_genl_family_id(cl, GENL_ID_VROUTER);
        return GENL_ID_VROUTER;
    }

    if ((ret = nl_build_get_family_id(cl, VROUTER_GENETLINK_FAMILY_NAME)))
        return ret;

    if (nl_sendmsg(cl) <= 0)
        return -errno;

    while (1) {
        ret = nl_recvmsg(cl);
        if (ret == EAGAIN)
            continue;
        else if (ret > 0)
            break;

        return -errno;
    }

    resp = nl_parse_reply(cl);
    if (!resp || resp->nl_type != NL_MSG_TYPE_GEN_CTRL ||
            resp->nl_op != CTRL_CMD_NEWFAMILY)
        return -EINVAL;

    msg = (struct genl_ctrl_message *)resp->nl_data;
    nl_set_genl_family_id(cl, msg->family_id);
#elif defined(__FreeBSD__)
    /* BSD doesn't check the value of family id, so set it to one */
    nl_set_genl_family_id(cl, 1);
#endif

    return cl->cl_genl_family_id;
}

#if defined(__linux__)
int
nl_build_attr_linkinfo(struct nl_client *cl, struct vn_if *ifp)
{
    char *link_info_buf;
    int len;
    struct nlattr *nla = (struct nlattr *)
        ((char *)cl->cl_buf + cl->cl_buf_offset);

    len = NLA_HDRLEN + NLA_HDRLEN +
        NLA_ALIGN(strlen(ifp->if_kind) + 1);

    if (cl->cl_buf_offset + len > cl->cl_buf_len)
        return -ENOMEM;

    nla->nla_len = len;
    nla->nla_type = IFLA_LINKINFO;

    link_info_buf = (char *)nla + NLA_HDRLEN;
    nla = (struct nlattr *)link_info_buf;
    nla->nla_len = len - NLA_HDRLEN;
    nla->nla_type = IFLA_INFO_KIND;

    link_info_buf += NLA_HDRLEN;
    strcpy(link_info_buf, ifp->if_kind);

    cl->cl_buf_offset += len;

    return 0;
}

int
nl_build_attr_ifname(struct nl_client *cl, struct vn_if *ifp)
{
    char *if_name_buf;
    int len;
    struct nlattr *nla = (struct nlattr *)
        ((char *)cl->cl_buf + cl->cl_buf_offset);

    len = NLA_HDRLEN + NLA_ALIGN(strlen(ifp->if_name) + 1);
    if (cl->cl_buf_offset + len > cl->cl_buf_len)
        return -ENOMEM;

    nla->nla_len = len;
    nla->nla_type = IFLA_IFNAME;

    if_name_buf = (char *)nla + NLA_HDRLEN;
    strcpy(if_name_buf, ifp->if_name);

    cl->cl_buf_offset += nla->nla_len;

    return 0;
}

int
nl_build_mac_address(struct nl_client *cl, struct vn_if *ifp)
{
    int len;
    char *mac_buf;
    struct nlattr *nla = (struct nlattr *)
        ((char *)cl->cl_buf + cl->cl_buf_offset);

    len = NLA_HDRLEN + NLA_ALIGN(6);
    if (cl->cl_buf_offset + len > cl->cl_buf_len)
        return -ENOMEM;

    nla->nla_len = len;
    nla->nla_type = IFLA_ADDRESS;

    mac_buf = (char *)nla + NLA_HDRLEN;
    memcpy(mac_buf, ifp->if_mac, sizeof(ifp->if_mac));

    cl->cl_buf_offset += nla->nla_len;

    return 0;
}


int
nl_build_ifinfo(struct nl_client *cl, struct vn_if *ifp)
{
    struct ifinfomsg *ifi_msg = (struct ifinfomsg *)
        (cl->cl_buf + cl->cl_buf_offset);

    if (cl->cl_buf_offset + NLMSG_ALIGN(sizeof(*ifi_msg)) >
            cl->cl_buf_len)
        return -ENOMEM;

    memset(ifi_msg, 0, sizeof(struct ifinfomsg));
    cl->cl_buf_offset += NLMSG_ALIGN(sizeof(struct ifinfomsg));

    return 0;
}

int
nl_build_if_create_msg(struct nl_client *cl, struct vn_if *ifp, uint8_t ack)
{
    int ret;
    uint32_t flags;

    if (!cl->cl_buf || cl->cl_buf_offset || !ifp)
        return -EINVAL;

    flags = NLM_F_REQUEST | NLM_F_CREATE;
    if (ack) {
        flags |= NLM_F_ACK;
    }
    ret = nl_build_nlh(cl, RTM_NEWLINK, flags);
    if (ret)
        return ret;

    ret = nl_build_ifinfo(cl, ifp);
    if (ret)
        return ret;

    ret = nl_build_mac_address(cl, ifp);
    if (ret)
        return ret;

    ret = nl_build_attr_ifname(cl, ifp);
    if (ret)
        return ret;

    ret = nl_build_attr_linkinfo(cl, ifp);
    if (ret)
        return ret;

    cl->cl_msg_len = cl->cl_buf_offset;
    nl_update_nlh(cl);

    return 0;
}

static int
nl_build_attr_dcb_set_all(struct nl_client *cl)
{
    uint8_t *dst;
    struct nlattr *nla = (struct nlattr *)nl_get_buf_ptr(cl);

    nla->nla_type = DCB_ATTR_SET_ALL;
    nla->nla_len = NLA_HDRLEN + sizeof(uint8_t);
    dst = (uint8_t *)nla + NLA_HDRLEN;
    *dst = 1;

    cl->cl_buf_offset += NLA_ALIGN(nla->nla_len);

    return 0;
}

static int
nl_build_attr_dcb_state(struct nl_client *cl, uint8_t state)
{
    uint8_t *dst;
    struct nlattr *attr = (struct nlattr *)nl_get_buf_ptr(cl);

    attr->nla_len = NLA_HDRLEN + NLA_ALIGN(sizeof(state));
    attr->nla_type = DCB_ATTR_STATE;

    dst = nl_get_buf_ptr(cl) + NLA_HDRLEN;
    memcpy(dst, &state, sizeof(state));

    cl->cl_buf_offset += attr->nla_len;
    return 0;
}

static int
nl_build_attr_dcb_ifname(struct nl_client *cl, uint8_t *ifname)
{
    uint8_t *dst;
    struct nlattr *attr = (struct nlattr *)nl_get_buf_ptr(cl);

    attr->nla_len = NLA_HDRLEN + strlen(ifname) + 1;
    attr->nla_type = DCB_ATTR_IFNAME;

    dst = nl_get_buf_ptr(cl) + NLA_HDRLEN;
    memcpy(dst, ifname, strlen(ifname));
    *(dst + strlen(ifname)) = '\0';

    cl->cl_buf_offset += NLA_ALIGN(attr->nla_len);
    return 0;
}

static int
nl_build_attr_set_dcbx(struct nl_client *cl, uint8_t dcbx)
{
    uint8_t *dst;
    struct nlattr *nla = (struct nlattr *)nl_get_buf_ptr(cl);

    nla->nla_len = NLA_HDRLEN + NLA_ALIGN(sizeof(uint8_t));
    nla->nla_type = DCB_ATTR_DCBX;

    dst = nl_get_buf_ptr(cl) + NLA_HDRLEN;
    *dst = dcbx;

    cl->cl_buf_offset += nla->nla_len;
    return 0;
}

static int
nl_build_attr_dcb_get_pgtx(struct nl_client *cl)
{
    unsigned int len = 0;
    struct nlattr *nla_p, *nla = (struct nlattr *)nl_get_buf_ptr(cl);

    nla_p = nla;
    nla->nla_len = len = NLA_HDRLEN;
    nla->nla_type = DCB_ATTR_PG_CFG;
    len += nla_p->nla_len;

    nla_p = (struct nlattr *)((uint8_t *)nla_p + nla_p->nla_len);
    nla_p->nla_type = DCB_PG_ATTR_TC_ALL;
    nla_p->nla_len = 2 * NLA_HDRLEN;
    len += nla_p->nla_len;

    nla_p = (struct nlattr *)((uint8_t *)nla_p + NLA_HDRLEN);
    nla_p->nla_type = DCB_TC_ATTR_PARAM_ALL;
    nla_p->nla_len = NLA_HDRLEN;
    len += nla_p->nla_len;

    nla_p = (struct nlattr *)((uint8_t *)nla_p + nla_p->nla_len);
    nla_p->nla_type = DCB_PG_ATTR_BW_ID_ALL;
    nla_p->nla_len = NLA_HDRLEN;
    len += nla_p->nla_len;

    nla->nla_len = len;
    cl->cl_buf_offset += len;

    return 0;
}

static int
nl_build_attr_dcb_pgtx(struct nl_client *cl, struct priority *p)
{
    uint8_t i, j, map, *dst;
    unsigned int len = 0, tc_attr_len;
    struct nlattr *nla_p, *tcattr, *nla = (struct nlattr *)nl_get_buf_ptr(cl);

    nla_p = nla;
    nla->nla_len = len = NLA_HDRLEN;
    nla->nla_type = DCB_ATTR_PG_CFG;

    nla_p += 1;
    for (i = DCB_PG_ATTR_TC_0; i <= DCB_PG_ATTR_TC_7; i++) {
        tcattr = nla_p;
        tcattr->nla_type = i;
        tcattr->nla_len = NLA_HDRLEN;

        tc_attr_len = 0;

        nla_p += 1;
        nla_p->nla_type = DCB_TC_ATTR_PARAM_STRICT_PRIO;
        nla_p->nla_len = NLA_HDRLEN + sizeof(uint8_t);
        dst = (uint8_t *)nla_p + NLA_HDRLEN;
        *dst = (p->tc_strictness & (1 << (i - DCB_PG_ATTR_TC_0)) ? 1 : 0);
        tc_attr_len += NLA_ALIGN(nla_p->nla_len);

        nla_p = (struct nlattr *)((uint8_t *)nla_p + NLA_ALIGN(nla_p->nla_len));
        nla_p->nla_len = NLA_HDRLEN + sizeof(uint8_t);
        nla_p->nla_type = DCB_TC_ATTR_PARAM_PGID;
        dst = (uint8_t *)nla_p + NLA_HDRLEN;
        *dst = p->tc_to_group[i - DCB_PG_ATTR_TC_0];
        tc_attr_len += NLA_ALIGN(nla_p->nla_len);

        if (p->tc_bw_pct[i - DCB_PG_ATTR_TC_0]) {
            nla_p = (struct nlattr *)((uint8_t *)nla_p +
                    NLA_ALIGN(nla_p->nla_len));
            nla_p->nla_len = NLA_HDRLEN + sizeof(uint8_t);
            nla_p->nla_type = DCB_TC_ATTR_PARAM_BW_PCT;
            dst = (uint8_t *)nla_p + NLA_HDRLEN;
            *dst = p->tc_bw_pct[i - DCB_PG_ATTR_TC_0];
            tc_attr_len += NLA_ALIGN(nla_p->nla_len);
        }

        map = 0;
        for (j = 0; j < sizeof(p->prio_to_tc); j++) {
            if (p->prio_to_tc[j] == (i - DCB_PG_ATTR_TC_0))
                map |= (1 << j);
        }

        nla_p = (struct nlattr *)((uint8_t *)nla_p +
                NLA_ALIGN(nla_p->nla_len));
        nla_p->nla_len = NLA_HDRLEN + sizeof(uint8_t);
        nla_p->nla_type = DCB_TC_ATTR_PARAM_UP_MAPPING;
        dst = (uint8_t *)nla_p + NLA_HDRLEN;
        *dst = map;
        tc_attr_len += NLA_ALIGN(nla_p->nla_len);

        tcattr->nla_len += tc_attr_len;
        len += tcattr->nla_len;
        nla_p = (struct nlattr *)((uint8_t *)nla_p + NLA_ALIGN(nla_p->nla_len));
    }

    for (i = DCB_PG_ATTR_BW_ID_0; i <= DCB_PG_ATTR_BW_ID_7; i++) {
        nla_p->nla_type = i;
        nla_p->nla_len = NLA_HDRLEN + sizeof(uint8_t);
        dst = (uint8_t *)nla_p + NLA_HDRLEN;
        *dst = p->prio_group_bw[i - DCB_PG_ATTR_BW_ID_0];
        len += NLA_ALIGN(nla_p->nla_len);

        nla_p = (struct nlattr *)((uint8_t *)nla_p + NLA_ALIGN(nla_p->nla_len));
    }

    nla->nla_len = len;
    cl->cl_buf_offset += len;

    return 0;
}

static int
nl_build_dcb_msg(struct nl_client *cl, uint8_t cmd)
{
    struct dcbmsg *dcb = (struct dcbmsg *)nl_get_buf_ptr(cl);

    dcb->cmd = cmd;
    dcb->dcb_family = AF_UNSPEC;
    dcb->dcb_pad = 0;

    cl->cl_buf_offset += sizeof(*dcb);

    return 0;
}

static bool
nl_dcb_set_cmd(uint8_t cmd)
{
    switch (cmd) {
    case DCB_CMD_SSTATE:
    case DCB_CMD_PGTX_SCFG:
    case DCB_CMD_SET_ALL:
    case DCB_CMD_SDCBX:
    case DCB_CMD_IEEE_SET:
        return true;

    default:
        break;
    }

    return false;
}

static int
nl_build_dcb_nl_msg(struct nl_client *cl, uint8_t *ifname,
        uint8_t cmd, uint8_t ack)
{
    int ret, msgtype;
    uint32_t flags;

    if (!cl->cl_buf || cl->cl_buf_offset)
        return -EINVAL;

    flags = NLM_F_REQUEST | NLM_F_CREATE;
    if (ack) {
        flags |= NLM_F_ACK;
    }

    if (nl_dcb_set_cmd(cmd)) {
        msgtype = RTM_SETDCB;
    } else {
        msgtype = RTM_GETDCB;
    }

    ret = nl_build_nlh(cl, msgtype, flags);
    if (ret)
        return ret;

    ret = nl_build_dcb_msg(cl, cmd);
    if (ret)
        return ret;

    ret = nl_build_attr_dcb_ifname(cl, ifname);
    if (ret)
        return ret;

    return ret;
}

static int
nl_parse_dcb_tc_attr(struct nlattr *nla, void *buf, uint8_t parent_attr_type)
{
    int ret;
    uint8_t byte, j;
    unsigned int processed = 0, nla_len;

    struct nlattr *nla_p;
    struct priority *p = (struct priority *)buf;

    switch (nla->nla_type) {
    case DCB_TC_ATTR_PARAM_PGID:
        byte = *(uint8_t *)(nla + 1);
        p->tc_to_group[parent_attr_type - DCB_PG_ATTR_TC_0] = byte;
        processed = NLA_ALIGN(NLA_HDRLEN + sizeof(uint8_t));
        break;

    case DCB_TC_ATTR_PARAM_UP_MAPPING:
        byte = *(uint8_t *)(nla + 1);
        if (byte) {
            for (j = 0; j < 8; j++) {
                if (byte & (1 << j)) {
                    p->prio_to_tc[j] = parent_attr_type - DCB_PG_ATTR_TC_0;
                }
            }
        }
        processed = NLA_ALIGN(NLA_HDRLEN + sizeof(uint8_t));
        break;

    case DCB_TC_ATTR_PARAM_STRICT_PRIO:
        byte = *(uint8_t *)(nla + 1);
        if (byte)
            p->tc_strictness |= (1 << (parent_attr_type - DCB_PG_ATTR_TC_0));
        processed = NLA_ALIGN(NLA_HDRLEN + sizeof(uint8_t));
        break;

    case DCB_TC_ATTR_PARAM_BW_PCT:
        processed = NLA_ALIGN(NLA_HDRLEN + sizeof(uint8_t));
        break;

    default:
        return -EINVAL;
    }

    return processed;
}


static int
nl_parse_dcb_pg_attr(struct nlattr *nla, void *buf)
{
    int ret;
    uint8_t byte;
    unsigned int processed = 0, nla_len;

    struct nlattr *nla_p;
    struct priority *p = (struct priority *)buf;

    nla_len = NLA_ALIGN(nla->nla_len);

    switch (nla->nla_type) {
    case DCB_PG_ATTR_TC_0:
    case DCB_PG_ATTR_TC_1:
    case DCB_PG_ATTR_TC_2:
    case DCB_PG_ATTR_TC_3:
    case DCB_PG_ATTR_TC_4:
    case DCB_PG_ATTR_TC_5:
    case DCB_PG_ATTR_TC_6:
    case DCB_PG_ATTR_TC_7:
        processed = NLA_HDRLEN;
        break;

    case DCB_PG_ATTR_BW_ID_0:
    case DCB_PG_ATTR_BW_ID_1:
    case DCB_PG_ATTR_BW_ID_2:
    case DCB_PG_ATTR_BW_ID_3:
    case DCB_PG_ATTR_BW_ID_4:
    case DCB_PG_ATTR_BW_ID_5:
    case DCB_PG_ATTR_BW_ID_6:
    case DCB_PG_ATTR_BW_ID_7:
        byte = *(uint8_t *)(nla + 1);
        p->prio_group_bw[nla->nla_type - DCB_PG_ATTR_BW_ID_0] = byte;
        processed = NLA_ALIGN(NLA_HDRLEN + sizeof(uint8_t));
        break;

    default:
        return -EINVAL;
    }

    nla_len -= NLA_ALIGN(processed);
    while (nla_len) {
        nla_p = (struct nlattr *)((uint8_t *)nla + NLA_ALIGN(processed));
        ret = nl_parse_dcb_tc_attr(nla_p, buf, nla->nla_type);
        if (ret < 0)
            return ret;

        processed += ret;
        nla_len -= NLA_ALIGN(ret);
    }

    return processed;
}

static int
nl_parse_dcb_ieee_attr_ets(struct nlattr *nla, void *buf)
{
    uint8_t i;

    struct priority *p = (struct priority *)buf;
    struct ieee_ets *ets;

    ets = (struct ieee_ets *)(nla + 1);
    memcpy(p->prio_group_bw, ets->tc_tx_bw, sizeof(ets->tc_tx_bw));
    p->tc_strictness = 0;
    for (i = 0; i < 8; i++) {
        if (ets->tc_tsa[i] == IEEE_8021QAZ_TSA_STRICT) {
            p->tc_strictness |= (1 << i);
        }
    }

    memcpy(p->prio_to_tc, ets->prio_tc, sizeof(ets->tc_tx_bw));
    for (i = 0; i < 8; i++) {
        p->tc_to_group[i] = i;
    }

    return nla->nla_len;
}

static int
nl_parse_dcb_ieee_attr(struct nlattr *nla, void *buf)
{
    int ret;

    switch (nla->nla_type) {
    case DCB_ATTR_IEEE_ETS:
        ret = nl_parse_dcb_ieee_attr_ets(nla, buf);
        break;

    default:
        ret = nla->nla_len;
        break;
    }

    return ret;
}

static int
nla_parse_dcb_ieee_response(struct nlattr *nla, void *buf)
{
    int ret;
    unsigned int processed = 0, nla_len;
    struct nlattr *nla_p;

    if (nla->nla_type != DCB_ATTR_IFNAME)
        return -EINVAL;
    nla_len = NLA_ALIGN(nla->nla_len);

    nla = (struct nlattr *)((uint8_t *)nla + nla_len);
    if (nla->nla_type != DCB_ATTR_IEEE)
        return -EINVAL;
    nla_len = NLA_ALIGN(nla->nla_len);
    processed += NLA_HDRLEN;
    nla_len -= NLA_HDRLEN;

    while (nla_len) {
        nla_p = (struct nlattr *)((uint8_t *)nla + NLA_ALIGN(processed));
        ret = nl_parse_dcb_ieee_attr(nla_p, buf);
        if (ret < 0)
            return ret;

        processed += NLA_ALIGN(ret);
        nla_len -= NLA_ALIGN(ret);
    }

    return processed;
}

static int
nla_parse_dcb_pg_response(struct nlattr *nla, void *buf)
{
    int ret;
    unsigned int processed = 0, nla_len;
    struct nlattr *nla_p;

    nla_len = NLA_ALIGN(nla->nla_len);
    if (!nla_len || (nla->nla_type != DCB_ATTR_PG_CFG))
        return -EINVAL;

    processed = NLA_HDRLEN;
    nla_len -= NLA_ALIGN(processed);

    while (nla_len) {
        nla_p = (struct nlattr *)((uint8_t *)nla + NLA_ALIGN(processed));
        ret = nl_parse_dcb_pg_attr(nla_p, buf);
        if (ret < 0)
            return ret;

        processed += ret;
        nla_len -= NLA_ALIGN(ret);
    }

    return processed;
}

static int
nl_parse_dcb_response(uint8_t *dcbm, uint8_t cmd, uint8_t attr, void *buf)
{
    int ret;
    struct nlattr *nla;
    struct dcbmsg *dcb = (struct dcbmsg *)dcbm;

    if (dcb->cmd != cmd) {
        return -EINVAL;
    }

    nla = (struct nlattr *)(dcb + 1);
    if (nla->nla_type != attr)
        return -EINVAL;

    if ((nla->nla_type == DCB_ATTR_PG_CFG) &&
            (cmd == DCB_CMD_PGTX_GCFG)) {
        return nla_parse_dcb_pg_response(nla, buf);
    } else if (cmd == DCB_CMD_IEEE_GET) {
        return nla_parse_dcb_ieee_response(nla, buf);
    }

    return *((uint8_t *)((uint8_t *)nla + NLA_HDRLEN));
}

int
nl_build_set_dcb_state_msg(struct nl_client *cl,
        uint8_t *ifname, uint8_t state)
{
    int ret;

    ret = nl_build_dcb_nl_msg(cl, ifname, DCB_CMD_SSTATE, 0);
    if (ret)
        return ret;

    ret = nl_build_attr_dcb_state(cl, state);
    if (ret)
        return ret;

    cl->cl_msg_len = cl->cl_buf_offset;
    nl_update_nlh(cl);

    return ret;
}

int
nl_build_get_dcb_state_msg(struct nl_client *cl, uint8_t *ifname)
{
    int ret;

    ret = nl_build_dcb_nl_msg(cl, ifname, DCB_CMD_GSTATE, 0);
    if (ret)
        return ret;

    cl->cl_msg_len = cl->cl_buf_offset;
    nl_update_nlh(cl);

    return 0;
}

int
nl_build_set_priority_config_msg(struct nl_client *cl, uint8_t *ifname,
        struct priority *p)
{
    int ret;

    ret = nl_build_dcb_nl_msg(cl, ifname, DCB_CMD_PGTX_SCFG, 0);
    if (ret)
        return ret;

    ret = nl_build_attr_dcb_pgtx(cl, p);
    if (ret)
        return ret;

    cl->cl_msg_len = cl->cl_buf_offset;
    nl_update_nlh(cl);

    return 0;
}

int
nl_build_get_priority_config_msg(struct nl_client *cl, uint8_t *ifname)
{
    int ret;

    ret = nl_build_dcb_nl_msg(cl, ifname, DCB_CMD_PGTX_GCFG, 0);
    if (ret)
        return ret;

    ret = nl_build_attr_dcb_get_pgtx(cl);
    if (ret)
        return ret;

    cl->cl_msg_len = cl->cl_buf_offset;
    nl_update_nlh(cl);

    return 0;
}

int
nl_build_set_dcb_all(struct nl_client *cl, uint8_t *ifname)
{
    int ret;

    ret = nl_build_dcb_nl_msg(cl, ifname, DCB_CMD_SET_ALL, 0);
    if (ret)
        return ret;

    ret = nl_build_attr_dcb_set_all(cl);
    if (ret)
        return ret;

    cl->cl_msg_len = cl->cl_buf_offset;
    nl_update_nlh(cl);

    return 0;
}

int
nl_build_set_dcbx(struct nl_client *cl, uint8_t *ifname,  uint8_t dcbx)
{
    int ret;

    ret = nl_build_dcb_nl_msg(cl, ifname, DCB_CMD_SDCBX, 0);
    if (ret)
        return ret;

    ret = nl_build_attr_set_dcbx(cl, dcbx);
    if (ret)
        return ret;

    cl->cl_msg_len = cl->cl_buf_offset;
    nl_update_nlh(cl);

    return 0;
}

int
nl_build_get_dcbx(struct nl_client *cl, uint8_t *ifname)
{
    int ret;

    ret = nl_build_dcb_nl_msg(cl, ifname, DCB_CMD_GDCBX, 0);
    if (ret)
        return ret;

    cl->cl_msg_len = cl->cl_buf_offset;
    nl_update_nlh(cl);

    return 0;
}

int
nl_dcb_parse_reply(struct nl_client *cl, uint8_t cmd, void *resp_buf)
{
    int ret = 0;
    uint8_t attr = DCB_ATTR_UNDEFINED;
    struct nl_response *resp;

    resp = nl_parse_reply(cl);
    if (resp) {
        if (resp->nl_type == NL_MSG_TYPE_ERROR) {
            printf("vRouter: DCB %d failed with error %d\n",
                    cmd, resp->nl_op);
            return resp->nl_op;
        }

        switch (cmd) {
        case DCB_CMD_SSTATE:
        case DCB_CMD_GSTATE:
            attr = DCB_ATTR_STATE;
            break;

        case DCB_CMD_SDCBX:
        case DCB_CMD_GDCBX:
            attr = DCB_ATTR_DCBX;
            break;

        case DCB_CMD_PGTX_SCFG:
        case DCB_CMD_PGTX_GCFG:
            attr = DCB_ATTR_PG_CFG;
            break;

        case DCB_CMD_IEEE_SET:
            attr = DCB_ATTR_IEEE;
            break;

        case DCB_CMD_IEEE_GET:
            attr = DCB_ATTR_IFNAME;
            break;

        default:
            break;
        }

        ret = nl_parse_dcb_response((uint8_t *)resp->nl_data, cmd,
                attr, resp_buf);
    }

    cl->cl_buf_offset = 0;
    return ret;
}

static int
nl_build_attr_ieee_ets(struct nl_client *cl, struct priority *p)
{
    unsigned int i;

    struct ieee_ets *ets;
    struct nlattr *nla_p, *nla = (struct nlattr *)nl_get_buf_ptr(cl);

    nla->nla_type = DCB_ATTR_IEEE;
    nla->nla_len = NLA_HDRLEN;

    nla_p = (struct nlattr *)(nla + 1);
    nla_p->nla_type = DCB_ATTR_IEEE_ETS;
    nla_p->nla_len = NLA_HDRLEN + sizeof(*ets);

    ets = (struct ieee_ets *)(nla_p + 1);
    memset(ets, 0, sizeof(*ets));

    ets->willing = 0;
    ets->ets_cap = 8;
    ets->cbs = 0;

    memcpy(&ets->tc_tx_bw, &p->prio_group_bw, sizeof(p->prio_group_bw));
    memcpy(&ets->prio_tc, &p->prio_to_tc, sizeof(p->prio_to_tc));

    for (i = 0; i < 8; i++) {
        if (p->tc_strictness & (1 << i)) {
            ets->tc_tsa[i] = IEEE_8021QAZ_TSA_STRICT;
        } else {
            ets->tc_tsa[i] = IEEE_8021QAZ_TSA_ETS;
        }
    }

    nla->nla_len += NLA_ALIGN(nla_p->nla_len);
    cl->cl_buf_offset += NLA_ALIGN(nla->nla_len);

    return 0;
}

int
nl_build_get_ieee_ets(struct nl_client *cl, uint8_t *ifname,
        struct priority *p)
{
    int ret;

    ret = nl_build_dcb_nl_msg(cl, ifname, DCB_CMD_IEEE_GET, 0);
    if (ret)
        return ret;

    cl->cl_msg_len = cl->cl_buf_offset;
    nl_update_nlh(cl);

    return 0;
}

int
nl_build_set_ieee_ets(struct nl_client *cl, uint8_t *ifname,
        struct priority *p)
{
    int ret;

    ret = nl_build_dcb_nl_msg(cl, ifname, DCB_CMD_IEEE_SET, 0);
    if (ret)
        return ret;

    ret = nl_build_attr_ieee_ets(cl, p);
    if (ret < 0)
        return ret;

    cl->cl_msg_len = cl->cl_buf_offset;
    nl_update_nlh(cl);

    return 0;
}


int
nl_dcb_sendmsg(struct nl_client *cl, uint8_t cmd, void *resp_buf)
{
    int ret;

    ret = nl_sendmsg(cl);
    if (ret <= 0)
        return -1;

    if ((ret = nl_recvmsg(cl)) > 0) {
        return nl_dcb_parse_reply(cl, cmd, resp_buf);
    }

    return ret;
}

#endif  /* __linux__ */
