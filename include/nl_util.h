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
#include "vr_response.h"

#define NL_RESP_DEFAULT_SIZE        512
#define NL_MSG_DEFAULT_SIZE         4096

#define NL_MSG_TYPE_ERROR           0
#define NL_MSG_TYPE_DONE            1
#define NL_MSG_TYPE_GEN_CTRL        2
#define NL_MSG_TYPE_FMLY            3

#define VR_NETLINK_PROTO_DEFAULT    0xFFFFFFFF

struct nl_response {
    uint8_t *nl_data;
    unsigned int nl_type;
    unsigned int nl_op;
    unsigned int nl_len;
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
    int cl_socket_domain;
    int cl_socket_type;
    int cl_socket_proto;
    int (*cl_recvmsg)(struct nl_client *);
    struct sockaddr *cl_sa;
    uint32_t cl_sa_len;
};


#define GENL_FAMILY_NAME_LEN            16

struct genl_ctrl_message {
    int family_id;
    char family_name[GENL_FAMILY_NAME_LEN];
};

#define NLA_DATA(nla)                   ((char *)nla + NLA_HDRLEN)
#define NLA_LEN(nla)                    (nla->nla_len - NLA_HDRLEN)
#define GENLMSG_DATA(buf)               ((char *)buf + GENL_HDRLEN)

/* Suppress NetLink error messages */
extern bool vr_ignore_nl_errors;

extern struct nl_client *nl_register_client(void);
extern void nl_free_client(struct nl_client *cl);
extern int nl_socket(struct nl_client *, int, int , int);
extern int nl_connect(struct nl_client *, uint32_t, uint16_t);
extern int nl_sendmsg(struct nl_client *);
extern int nl_client_datagram_recvmsg(struct nl_client *);
extern int nl_client_stream_recvmsg(struct nl_client *);
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
extern int get_vrouter_pid(void);

extern char *vr_extract_token(char *, char);
extern bool vr_valid_ipv6_address(const char *);
extern bool vr_valid_ipv4_address(const char *);
extern bool vr_valid_mac_address(const char *);
extern char *vr_proto_string(unsigned short);

extern int vr_recvmsg(struct nl_client *cl, bool dump);
extern int vr_sendmsg(struct nl_client *, void *, char *);
extern struct nl_client *vr_get_nl_client(unsigned int);

extern int vr_response_common_process(vr_response *, bool *);

extern unsigned long vr_sum_drop_stats(vr_drop_stats_req *);
extern void vr_drop_stats_req_destroy(vr_drop_stats_req *);
extern vr_drop_stats_req *vr_drop_stats_req_get_copy(vr_drop_stats_req *);
extern int vr_send_drop_stats_get(struct nl_client *, unsigned int, int);

extern int vr_send_interface_dump(struct nl_client *, unsigned int, int, int);
extern int vr_send_interface_get(struct nl_client *, unsigned int,
                int, int, int);
extern int vr_send_interface_delete(struct nl_client *, unsigned int,
        char *, int);
extern int vr_send_interface_add(struct nl_client *, int, char *, int,
        int, int, int, unsigned int, unsigned int, int8_t *, int8_t);
extern vr_interface_req *vr_interface_req_get_copy(vr_interface_req *);
extern void vr_interface_req_destroy(vr_interface_req *);

extern int vr_send_mem_stats_get(struct nl_client *, unsigned intid);

extern int vr_send_mirror_dump(struct nl_client *, unsigned int, int);
extern int vr_send_mirror_get(struct nl_client *, unsigned int, unsigned int);
extern int vr_send_mirror_delete(struct nl_client *,
        unsigned int, unsigned int);
extern int vr_send_mirror_add(struct nl_client *, unsigned int,
        unsigned int, int, unsigned int);
extern void vr_mirror_req_destroy(vr_mirror_req *);
extern vr_mirror_req *vr_mirror_get_req_copy(vr_mirror_req *);

extern int vr_send_mpls_add(struct nl_client *, unsigned int, unsigned int,
        unsigned int);
extern int vr_send_mpls_get(struct nl_client *, unsigned int, unsigned int);
extern int vr_send_mpls_dump(struct nl_client *, unsigned int, int);
extern int vr_send_mpls_delete(struct nl_client *, unsigned int, unsigned int);

extern char *vr_nexthop_type_string(vr_nexthop_req *);
extern bool vr_nexthop_req_has_vif(vr_nexthop_req *);
extern int vr_send_nexthop_delete(struct nl_client *, unsigned int,
        unsigned int);
extern int vr_send_nexthop_dump(struct nl_client *, unsigned int, int);
extern int vr_send_nexthop_get(struct nl_client *, unsigned int, unsigned int);
extern int vr_send_nexthop_composite_add(struct nl_client *, unsigned int,
        int, unsigned int, int, unsigned int, unsigned int *, unsigned int *);
extern int vr_send_nexthop_encap_tunnel_add(struct nl_client *, unsigned int,
        unsigned int, int, unsigned int, int, int, int8_t *, int8_t *,
        struct in_addr, struct in_addr, int, int);
extern int vr_send_nexthop_add(struct nl_client *, unsigned int,
        unsigned int, int, unsigned int, int, int);
extern vr_nexthop_req *vr_nexthop_req_get_copy(vr_nexthop_req *);
extern void vr_nexthop_req_destroy(vr_nexthop_req *);


extern void address_mask(uint8_t *, uint8_t, unsigned int);
extern int vr_send_route_dump(struct nl_client *, unsigned int, unsigned int,
        unsigned int, uint8_t *, unsigned int);
extern int vr_send_route_get(struct nl_client *, unsigned int, unsigned int,
        unsigned int family, uint8_t *, unsigned int, uint8_t *);
extern int vr_send_route_delete(struct nl_client *, unsigned int, unsigned int,
        unsigned int family, uint8_t *, unsigned int, unsigned int,
        int, uint8_t *, uint32_t, unsigned ints);
extern int vr_send_route_add(struct nl_client *, unsigned int, unsigned int,
        unsigned int family, uint8_t *, unsigned int, unsigned int,
        int, uint8_t *, uint32_t, unsigned int);
extern vr_route_req *vr_route_req_get_copy(vr_route_req *);
extern void vr_route_req_destroy(vr_route_req *);

extern int vr_send_vrf_assign_dump(struct nl_client *, unsigned int,
        unsigned int, int);
extern int vr_send_vrf_assign_set(struct nl_client *, unsigned int,
                unsigned int, unsigned int, unsigned int);

extern int vr_send_vrf_stats_dump(struct nl_client *, unsigned int, int);
extern int vr_send_vrf_stats_get(struct nl_client *, unsigned int, unsigned int);

extern int vr_send_vrouter_get(struct nl_client *, unsigned int);
extern int vr_send_vrouter_set_logging(struct nl_client *, unsigned int,
        unsigned int, unsigned int *, unsigned int,
        unsigned int *, unsigned int);

extern int vr_send_vxlan_add(struct nl_client *, unsigned int,
        unsigned int, unsigned int);
extern int vr_send_vxlan_get(struct nl_client *, unsigned int, unsigned int);
extern int vr_send_vxlan_dump(struct nl_client *, unsigned int, int);
extern int vr_send_vxlan_delete(struct nl_client *, unsigned int, unsigned int);

extern int vr_send_qos_map_get(struct nl_client *, unsigned int, unsigned int);
extern int vr_send_qos_map_dump(struct nl_client *, unsigned int, int);
extern int vr_send_qos_map_add(struct nl_client *, unsigned int, unsigned int,
        uint8_t *, uint8_t, uint8_t *, uint8_t *, uint8_t,
        uint8_t *, uint8_t *, uint8_t, uint8_t *);

extern int vr_send_fc_map_get(struct nl_client *, unsigned int, uint8_t);
extern int vr_send_fc_map_dump(struct nl_client *, unsigned int, int);
extern int vr_send_fc_map_add(struct nl_client *, unsigned int, int16_t *,
        uint8_t, uint8_t *, uint8_t *, uint8_t *, uint8_t *);



#ifdef __cplusplus
}
#endif
#endif /* __NL_UTIL_H__ */
