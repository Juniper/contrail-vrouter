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

#include <net/if.h> /* For IFNAMSIZ */
#include <stdbool.h> /* For bool */
#include "vr_utils.h"
#include "vr_response.h"

#define VR_DEF_NETLINK_PORT         20914
#define VR_DEF_SOCKET_DIR           "/var/run/vrouter"
#define VR_DEF_NETLINK_PATH         "/var/run/vrouter/dpdk_netlink"

#define NL_RESP_DEFAULT_SIZE        512
#define NL_MSG_DEFAULT_SIZE         4096

#define NL_MSG_TYPE_ERROR           0
#define NL_MSG_TYPE_DONE            1
#define NL_MSG_TYPE_GEN_CTRL        2
#define NL_MSG_TYPE_FMLY            3

#define VR_NETLINK_PROTO_DEFAULT    -1
#define VR_NETLINK_PROTO_TEST       -2

#define BRIDGE_TABLE_DEV            "/dev/vr_bridge"
#define FLOW_TABLE_DEV              "/dev/flow"

#ifdef _WIN32
#define CLEAN_SCREEN_CMD        "cls"
#else
#define CLEAN_SCREEN_CMD        "clear"
#endif

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

#ifdef _WIN32
    HANDLE cl_win_pipe;
#else
    int cl_sock;
    int cl_socket_domain;

    struct sockaddr *cl_sa;
    uint32_t cl_sa_len;
#endif

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
    uint8_t *cl_attr;
    int (*cl_recvmsg)(struct nl_client *, bool);
};


#define GENL_FAMILY_NAME_LEN            16

struct genl_ctrl_message {
    int family_id;
    char family_name[GENL_FAMILY_NAME_LEN];
};

#define NLA_DATA(nla)                   ((char *)nla + NLA_HDRLEN)
#define NLA_LEN(nla)                    (nla->nla_len - NLA_HDRLEN)
#define GENLMSG_DATA(buf)               ((char *)buf + GENL_HDRLEN)

struct nl_sandesh_callbacks {
    void (*vrouter_ops_process)(void *);
    void (*vr_flow_req_process)(void *);
    void (*vr_flow_response_process)(void *);
    void (*vr_route_req_process)(void *);
    void (*vr_interface_req_process)(void *);
    void (*vr_mpls_req_process)(void *);
    void (*vr_mirror_req_process)(void *);
    void (*vr_response_process)(void *);
    void (*vr_nexthop_req_process)(void *);
    void (*vr_vrf_assign_req_process)(void *);
    void (*vr_vrf_stats_req_process)(void *);
    void (*vr_pkt_drop_log_req_process)(void *);
    void (*vr_drop_stats_req_process)(void *);
    void (*vr_vxlan_req_process)(void *);
    void (*vr_mem_stats_req_process)(void *);
    void (*vr_fc_map_req_process)(void *);
    void (*vr_qos_map_req_process)(void *);
    void (*vr_flow_table_data_process)(void *);
    void (*vr_bridge_table_data_process)(void *);
    void (*vr_hugepage_config_process)(void *);
};

extern struct nl_sandesh_callbacks nl_cb;

/* Suppress NetLink error messages */
extern bool vr_ignore_nl_errors;
extern char *vr_socket_dir;
extern uint16_t vr_netlink_port;


extern struct nl_client *nl_register_client(void);
extern void nl_free_client(struct nl_client *cl);
extern int nl_socket(struct nl_client *, int, int , int);
extern int nl_connect(struct nl_client *, uint32_t, uint16_t);
extern int nl_sendmsg(struct nl_client *);
extern int nl_client_datagram_recvmsg(struct nl_client *, bool);
extern int nl_client_stream_recvmsg(struct nl_client *, bool);
extern int nl_recvmsg(struct nl_client *);
extern int nl_recvmsg_waitall(struct nl_client *);
extern struct nl_response *nl_parse_reply(struct nl_client *);
extern struct nl_response *nl_parse_reply_os_specific(struct nl_client *);
extern struct nl_response *nl_parse_gen_nh(struct nl_client *);
extern struct nl_response *nl_parse_gen_mpls(struct nl_client *);
extern struct nl_response *nl_parse_gen_ctrl(struct nl_client *);
extern void nl_set_genl_family_id(struct nl_client *, unsigned int);

extern int nl_build_if_dump_msg(struct nl_client *cl);
extern struct nl_response *nl_set_resp_err(struct nl_client *, int);

extern int nl_init_generic_client_req(struct nl_client *nl, int family);
extern void nl_free(struct nl_client *nl);
extern void nl_free_os_specific(struct nl_client *cl);
extern void nl_reset_cl_sock(struct nl_client *cl);
extern void nl_init_generic_client_resp(struct nl_client *cl, char *resp,
                                        int resp_len);
extern int nl_build_nlh(struct nl_client *, uint32_t, uint32_t);
extern void nl_update_nlh(struct nl_client *);
extern int nl_build_genlh(struct nl_client *, uint8_t, uint8_t);

extern int nl_build_if_create_msg(struct nl_client *, struct vn_if *, uint8_t);
extern int nl_build_header(struct nl_client *, unsigned char **, uint32_t *);
extern void nl_update_header(struct nl_client *, int);
extern int nl_build_family_name_attr(struct nl_client *, char *);
extern int nl_build_get_family_id(struct nl_client *, char *);

extern int nl_build_set_dcb_state_msg(struct nl_client *, uint8_t *, uint8_t);
extern int nl_build_get_dcb_state_msg(struct nl_client *, uint8_t *);
extern int nl_build_set_priority_config_msg(struct nl_client *, uint8_t *,
        struct priority *);
extern int nl_build_get_priority_config_msg(struct nl_client *, uint8_t *);
extern int nl_build_set_dcb_all(struct nl_client *, uint8_t *);
extern int nl_build_set_dcbx(struct nl_client *, uint8_t *,  uint8_t);
extern int nl_build_get_dcbx(struct nl_client *, uint8_t *);
extern int nl_build_set_ieee_ets(struct nl_client *, uint8_t *,
        struct priority *);
extern int nl_build_get_ieee_ets(struct nl_client *, uint8_t *,
        struct priority *);
extern int nl_dcb_parse_reply(struct nl_client *, uint8_t, void *);
extern int nl_dcb_sendmsg(struct nl_client *, uint8_t, void *);
extern int nl_parse_dcb_state(uint8_t *);

extern int nl_get_sandesh_attr_size();
extern int nl_get_attr_hdr_size();
extern uint8_t *nl_get_buf_ptr(struct nl_client *cl);
extern uint32_t nl_get_buf_len(struct nl_client *cl);
extern void nl_build_attr(struct nl_client *cl, int len, int attr);
extern void nl_update_attr_len(struct nl_client *, int);
extern int vrouter_obtain_family_id(struct nl_client *cl);
extern int get_vrouter_pid(void);

extern char *vr_extract_token(char *, char);
extern bool vr_valid_ipv6_address(const char *);
extern bool vr_valid_ipv4_address(const char *);
extern bool vr_valid_mac_address(const char *);
extern char *vr_proto_string(unsigned short);

extern int vr_recvmsg(struct nl_client *cl, bool dump);
extern int vr_recvmsg_waitall(struct nl_client *cl, bool dump);
extern int vr_sendmsg(struct nl_client *, void *, char *);
extern struct nl_client *vr_get_nl_client(int);

extern int vr_response_common_process(vr_response *, bool *);

extern const char *vr_table_map(int, unsigned int, const char *, size_t, void **);
extern const char *vr_table_unlink(const char *);
extern uint64_t vr_sum_drop_stats(vr_drop_stats_req *);
extern void vr_drop_stats_req_destroy(vr_drop_stats_req *);
extern vr_drop_stats_req *vr_drop_stats_req_get_copy(vr_drop_stats_req *);
extern int vr_send_drop_stats_get(struct nl_client *, unsigned int,
        short);
extern int vr_drop_stats_reset(struct nl_client *);
extern int vr_send_interface_dump(struct nl_client *, unsigned int, int, int);
extern int vr_send_interface_get(struct nl_client *, unsigned int,
                int, int, int, int);
extern int vr_send_interface_delete(struct nl_client *, unsigned int,
        char *, int);
extern int vr_send_interface_add(struct nl_client *, int, char *, int,
        int, int, int, unsigned int, unsigned int, int8_t *, int8_t, const char *);
extern vr_interface_req *vr_interface_req_get_copy(vr_interface_req *);
extern void vr_interface_req_destroy(vr_interface_req *);

extern int vr_send_mem_stats_get(struct nl_client *, unsigned intid);

extern int vr_send_mirror_dump(struct nl_client *, unsigned int, int);
extern int vr_send_mirror_get(struct nl_client *, unsigned int, unsigned int);
extern int vr_send_mirror_delete(struct nl_client *,
        unsigned int, unsigned int);
extern int vr_send_mirror_add(struct nl_client *, unsigned int,
        unsigned int, int, unsigned int, int);
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
        int, unsigned int, int, unsigned int, unsigned int *, unsigned
        int *, unsigned int);
extern int vr_send_nexthop_encap_tunnel_add(struct nl_client *, unsigned int,
        unsigned int, int, unsigned int, int, int, int8_t *, int8_t *,
        struct in_addr, struct in_addr, int, int, int8_t *);
extern int vr_send_nexthop_add(struct nl_client *, unsigned int,
        unsigned int, int, unsigned int, int, int);
extern vr_nexthop_req *vr_nexthop_req_get_copy(vr_nexthop_req *);
extern void vr_nexthop_req_destroy(vr_nexthop_req *);
extern int vr_send_pbb_tunnel_add(struct nl_client *, unsigned int, int,
        unsigned int, int, int8_t *, unsigned int, unsigned int);


extern void address_mask(uint8_t *, uint8_t, unsigned int);
extern int vr_send_route_dump(struct nl_client *, unsigned int, unsigned int,
        unsigned int, uint8_t *);
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


extern int vr_send_set_dcb_state(struct nl_client *, uint8_t *, uint8_t);
extern int vr_send_set_dcbx(struct nl_client *, uint8_t *, uint8_t);
extern int vr_send_set_priority_config(struct nl_client *, uint8_t *,
        struct priority *);

extern int vr_send_get_dcb_state(struct nl_client *, uint8_t *);
extern int vr_send_get_dcbx(struct nl_client *, uint8_t *);
extern int vr_send_get_priority_config(struct nl_client *, uint8_t *,
        struct priority *);
extern int vr_send_set_dcb_all(struct nl_client *, uint8_t *);
extern int vr_send_set_ieee_ets(struct nl_client *, uint8_t *,
        struct priority *);
extern int vr_send_get_ieee_ets(struct nl_client *, uint8_t *,
        struct priority *);
extern void vr_print_drop_stats(vr_drop_stats_req *, int);

#ifdef _WIN32
extern int win_setup_nl_client(struct nl_client *, unsigned int);
extern int win_nl_sendmsg(struct nl_client *);
extern int win_nl_client_recvmsg(struct nl_client *, bool);

extern const LPCTSTR KSYNC_PATH;
#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif
#endif /* __NL_UTIL_H__ */
