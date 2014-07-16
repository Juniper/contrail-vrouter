/*
 * nl_util.h --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __NL_UTIL_H__
#define __NL_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "vr_utils.h"
#define NL_RESP_DEFAULT_SIZE        512
#define NL_MSG_DEFAULT_SIZE         4096

#define NL_MSG_TYPE_ERROR           0
#define NL_MSG_TYPE_DONE            1
#define NL_MSG_TYPE_GEN_CTRL        2
#define NL_MSG_TYPE_FMLY            3

struct nl_response {
    unsigned int nl_type;
    unsigned int nl_op;
    unsigned int nl_len;
    uint8_t  *nl_data;
};

struct nl_client {
    char *cl_buf;
    /* length of the buffer in cl_buf */
    unsigned int cl_buf_len;

    int cl_sock;
    unsigned int cl_sock_protocol;
    unsigned int cl_genl_family_id;

    uint32_t cl_buf_offset;
    uint32_t cl_msg_start;
    /* netlink message length */
    uint32_t cl_msg_len;
    /* length of the message received from recvmsg */
    uint32_t cl_recv_len;
    uint32_t cl_id;
    uint32_t cl_seq;
    struct nl_response resp;
    unsigned int cl_resp_buf_len;
    uint8_t *cl_resp_buf;
};


#define GENL_FAMILY_NAME_LEN            16

struct genl_ctrl_message {
    int family_id;
    char family_name[GENL_FAMILY_NAME_LEN];
};

#define NLA_DATA(nla)                   ((char *)nla + NLA_HDRLEN)
#define NLA_LEN(nla)                    (nla->nla_len - NLA_HDRLEN)
#define GENLMSG_DATA(buf)               ((char *)buf + GENL_HDRLEN)

extern struct nl_client *nl_register_client(void);
extern void nl_free_client(struct nl_client *cl);
extern int nl_socket(struct nl_client *, unsigned int);
extern int nl_sendmsg(struct nl_client *);
extern int nl_recvmsg(struct nl_client *);
extern struct nl_response *nl_parse_reply(struct nl_client *);
extern struct nl_response *nl_parse_gen_nh(struct nl_client *);
extern struct nl_response *nl_parse_gen_mpls(struct nl_client *);
extern struct nl_response *nl_parse_gen_ctrl(struct nl_client *);
extern void nl_set_genl_family_id(struct nl_client *, unsigned int);

extern int nl_build_if_dump_msg(struct nl_client *cl);
extern struct nl_response *nl_set_resp_err(struct nl_client *, int);

extern int nl_init_generic_client_req(struct nl_client *nl, int family);
extern void nl_free(struct nl_client *nl);
extern void nl_init_generic_client_resp(struct nl_client *cl, char *resp,
                                        int resp_len);
extern int nl_build_nlh(struct nl_client *, uint32_t, uint32_t);
extern void nl_update_nlh(struct nl_client *);
extern int nl_build_genlh(struct nl_client *, uint8_t, uint8_t);
extern int nl_build_if_create_msg(struct nl_client *cl, struct vn_if *ifp, uint8_t ack);
extern int nl_build_header(struct nl_client *cl, unsigned char **buf, uint32_t *buf_len);
extern void nl_update_header(struct nl_client *cl, int data_len);
extern int nl_build_family_name_attr(struct nl_client *cl, char *family);
extern int nl_build_get_family_id(struct nl_client *cl, char *family);
extern int nl_get_sandesh_attr_size();
extern int nl_get_attr_hdr_size();
extern uint8_t *nl_get_buf_ptr(struct nl_client *cl);
extern uint32_t nl_get_buf_len(struct nl_client *cl);
extern void nl_build_attr(struct nl_client *cl, int len, int attr);
extern int vrouter_get_family_id(struct nl_client *cl);

#ifdef __cplusplus
}
#endif
#endif /* __NL_UTIL_H__ */
