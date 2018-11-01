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
#include <linux/socket.h>
#endif

#include <stdint.h>
#include <net/if.h>
#include <netinet/in.h>
#include "vr_types.h"
#include "nl_util.h"
#include "vr_genetlink.h"
#include "vr_os.h"

extern struct nl_response *nl_parse_gen(struct nl_client *);

uint16_t vr_netlink_port = VR_DEF_NETLINK_PORT;
char *vr_socket_dir = VR_DEF_SOCKET_DIR;
struct nl_sandesh_callbacks nl_cb;

void
vrouter_ops_process(void *s_req)
{
    if (nl_cb.vrouter_ops_process) {
        nl_cb.vrouter_ops_process(s_req);
    }
}

void
vr_nexthop_req_process(void *s_req)
{
    if (nl_cb.vr_nexthop_req_process) {
        nl_cb.vr_nexthop_req_process(s_req);
    }
}


void
vr_flow_req_process(void *s_req)
{
    if (nl_cb.vr_flow_req_process) {
        nl_cb.vr_flow_req_process(s_req);
    }
}

void
vr_flow_response_process(void *s_req)
{
    if (nl_cb.vr_flow_response_process) {
        nl_cb.vr_flow_response_process(s_req);
    }
}

void
vr_flow_table_data_process(void *s_req)
{
    if (nl_cb.vr_flow_table_data_process) {
        nl_cb.vr_flow_table_data_process(s_req);
    }
}

void
vr_route_req_process(void *s_req)
{
    if (nl_cb.vr_route_req_process) {
        nl_cb.vr_route_req_process(s_req);
    }
}

void
vr_interface_req_process(void *s_req)
{
    if (nl_cb.vr_interface_req_process) {
        nl_cb.vr_interface_req_process(s_req);
    }
}

void
vr_mpls_req_process(void *s_req)
{
    if (nl_cb.vr_mpls_req_process) {
        nl_cb.vr_mpls_req_process(s_req);
    }
}

void
vr_mirror_req_process(void *s_req)
{
    if (nl_cb.vr_mirror_req_process) {
        nl_cb.vr_mirror_req_process(s_req);
    }
}

void
vr_response_process(void *s_req)
{
    if (nl_cb.vr_response_process) {
        nl_cb.vr_response_process(s_req);
    }
}


void
vr_vrf_assign_req_process(void *s_req)
{
    if (nl_cb.vr_vrf_assign_req_process) {
        nl_cb.vr_vrf_assign_req_process(s_req);
    }
}

void
vr_vrf_stats_req_process(void *s_req)
{
    if (nl_cb.vr_vrf_stats_req_process) {
        nl_cb.vr_vrf_stats_req_process(s_req);
    }
}

void
vr_drop_stats_req_process(void *s_req)
{
    if (nl_cb.vr_drop_stats_req_process) {
        nl_cb.vr_drop_stats_req_process(s_req);
    }
}

void
vr_vxlan_req_process(void *s_req)
{
    if (nl_cb.vr_vxlan_req_process) {
        nl_cb.vr_vxlan_req_process(s_req);
    }
}

void
vr_mem_stats_req_process(void *s_req)
{
    if (nl_cb.vr_mem_stats_req_process) {
        nl_cb.vr_mem_stats_req_process(s_req);
    }
}

void
vr_qos_map_req_process(void *s_req)
{
    if (nl_cb.vr_qos_map_req_process) {
        nl_cb.vr_qos_map_req_process(s_req);
    }
}

void
vr_fc_map_req_process(void *s_req)
{
    if (nl_cb.vr_fc_map_req_process) {
        nl_cb.vr_fc_map_req_process(s_req);
    }
}

void
vr_bridge_table_data_process(void *s_req)
{
    if (nl_cb.vr_bridge_table_data_process) {
        nl_cb.vr_bridge_table_data_process(s_req);
    }
}

void
vr_hugepage_config_process(void *s_req)
{
    if (nl_cb.vr_hugepage_config_process) {
        nl_cb.vr_hugepage_config_process(s_req);
    }
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
    nl_free_os_specific(cl);

    cl->cl_buf_offset = 0;
    cl->cl_buf_len = 0;
    if (cl->cl_buf) {
        free(cl->cl_buf);
        cl->cl_buf = NULL;
    }

    cl->cl_resp_buf_len = 0;
    if (cl->cl_resp_buf) {
        free(cl->cl_resp_buf);
        cl->cl_resp_buf = NULL;
    }

    cl->cl_recvmsg = NULL;
}

int
nl_recvmsg(struct nl_client *cl)
{
    return cl->cl_recvmsg(cl, false);
}

int
nl_recvmsg_waitall(struct nl_client *cl)
{
    return cl->cl_recvmsg(cl, true);
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
}

void
nl_set_rcv_len(struct nl_client *cl, unsigned int rcv_len)
{
    cl->cl_recv_len = rcv_len;
    cl->cl_buf_offset = 0;
    cl->cl_msg_len = 0;
}

void
nl_set_genl_family_id(struct nl_client *cl, unsigned int family_id)
{
    cl->cl_genl_family_id = family_id;
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
    nl_reset_cl_sock(cl);

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
}

int
nl_init_generic_client_req(struct nl_client *cl, int family)
{
    memset(cl, 0, sizeof(*cl));
    cl->cl_buf = malloc(NL_MSG_DEFAULT_SIZE);
    if (!cl->cl_buf)
        goto exit_register;
    cl->cl_buf_len = NL_MSG_DEFAULT_SIZE;
    cl->cl_genl_family_id = family;
    nl_reset_cl_sock(cl);

    return 1;

exit_register:
    return 0;
}

struct nl_response *
nl_parse_reply(struct nl_client *cl)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)(cl->cl_buf + cl->cl_buf_offset);
    struct nlmsgerr *err;
    struct nl_response *resp = &cl->resp;

    memset(resp, 0, sizeof(*resp));
    resp->nl_type = NL_MSG_TYPE_ERROR;
    if (cl->cl_buf_offset + NLMSG_HDRLEN > cl->cl_recv_len)
        return NULL;

    cl->cl_msg_len = nlh->nlmsg_len;
    cl->cl_msg_start = cl->cl_buf_offset;
    if (cl->cl_msg_len + cl->cl_buf_offset > cl->cl_recv_len)
        return nl_set_resp_err(cl, -ENOMEM);

    cl->cl_buf_offset += NLMSG_HDRLEN;

    if (nlh->nlmsg_type == NLMSG_DONE) {
        resp->nl_type = NL_MSG_TYPE_DONE;
        return resp;
    }

    if (nlh->nlmsg_type == NETLINK_GENERIC) {
        resp->nl_type = NL_MSG_TYPE_GEN_CTRL;
        resp = nl_parse_gen(cl);
        return resp;
    }

    if (nlh->nlmsg_type == cl->cl_genl_family_id) {
        resp->nl_type = NL_MSG_TYPE_FMLY;
        resp = nl_parse_gen(cl);
        return resp;
    }

    resp = nl_parse_reply_os_specific(cl);
    if (resp)
        return resp;

    err = (struct nlmsgerr *)nl_get_buf_ptr(cl);
    return nl_set_resp_err(cl, err->error);
}
