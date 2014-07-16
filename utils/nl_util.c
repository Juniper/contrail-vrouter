/*
 * nl_util.c -- netlink utility functions common for all the utilities
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

#if defined(__linux__)
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/genetlink.h>
#include <linux/sockios.h>
#endif

#include <stdint.h>
#include <net/if.h>
#include "nl_util.h"
#include "vr_genetlink.h"
#include "vr_os.h"

#define VROUTER_GENETLINK_FAMILY_NAME "vrouter"

unsigned int nl_client_ids;

extern struct nl_response *nl_parse_gen(struct nl_client *);

extern void vr_ops_process (void *a) __attribute__((weak));
extern void vr_flow_req_process(void *s_req) __attribute__((weak)); 
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
            strncpy(msg->family_name, NLA_DATA(nla), GENL_FAMILY_NAME_LEN - 1);
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

    /* Update the netlink header len */
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
nl_build_attr(struct nl_client *cl, int len, int attr)
{
    struct nlattr *nla;

    nla = (struct nlattr *)(cl->cl_buf + cl->cl_buf_offset);
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

    cl->cl_buf = NULL;
    cl->cl_resp_buf = NULL;
    cl->cl_buf_offset = 0;
    cl->cl_buf_len = 0;
    cl->cl_resp_buf_len = 0;

    return;
}

int
nl_socket(struct nl_client *cl, unsigned int protocol)
{
#if defined(__linux__)
    struct sockaddr_nl sa;
#endif

    if (cl->cl_sock >= 0)
        return -EEXIST;

#if defined(__linux__)
    cl->cl_sock = socket(AF_NETLINK, SOCK_DGRAM, protocol);
#elif defined(__FreeBSD__)
    /*
     * Fake Contrail socket has only one protocol for handling
     * sandesh protocol, so zero must be passed as a parameter
     */
    cl->cl_sock = socket(AF_VENDOR00, SOCK_DGRAM, 0);
#endif
    if (cl->cl_sock < 0)
        return cl->cl_sock;

#if defined(__linux__)
    /* In simple configuration we test on BSD, binding is not
     * required. It will be implemented later.
     */
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = cl->cl_id;
    bind(cl->cl_sock, (struct sockaddr *)&sa, sizeof(sa));
#endif

    cl->cl_sock_protocol = protocol;

    return cl->cl_sock;
}


int
nl_recvmsg(struct nl_client *cl)
{
    int ret;
#if defined (__linux__)
    struct sockaddr_nl sa;
#endif
    struct msghdr msg;
    struct iovec iov;

    memset(&msg, 0, sizeof(msg));
#if defined(__linux__)
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
#endif

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
nl_sendmsg(struct nl_client *cl)
{
#if defined (__linux__)
    struct sockaddr_nl sa;
#endif
    struct msghdr msg;
    struct iovec iov;

    memset(&msg, 0, sizeof(msg));
#if defined (__linux__)
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    msg.msg_name = &sa;
    msg.msg_namelen = sizeof(sa);
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

    /* this really is OK... */
    cl->cl_id = __sync_fetch_and_add(&nl_client_ids, 1);

    cl->cl_sock = -1;

    return cl;

exit_register:
    if (cl)
        nl_free(cl);

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
    } else {
        return nl_set_resp_err(cl, NL_MSG_TYPE_ERROR);
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
    if ((ret = nl_build_get_family_id(cl, VROUTER_GENETLINK_FAMILY_NAME)))
        return ret;

    if (nl_sendmsg(cl) <= 0)
        return -errno;

    if (nl_recvmsg(cl) <= 0)
        return -errno;

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
#endif  /* __linux__ */
