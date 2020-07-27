/*
 * vr_info.h -- vr_info header
 *
 * Copyright (c) 2020 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_INFO_H__
#define __VR_INFO_H__

/* Register vr_info msg and its corresponsding callback below.
 * */
#define VR_INFO_REG(X) \
    X(INFO_VER,  info_get_version, KERNEL) \
    X(INFO_VER_DPDK,  info_get_dpdk_version, DPDK) \
    X(INFO_BOND, info_get_bond,    DPDK) \
    X(INFO_LACP, info_get_lacp,    DPDK) \
    X(INFO_MEMPOOL, info_get_mempool,    DPDK) \
    X(INFO_STATS, info_get_stats, DPDK) \
    X(INFO_XSTATS, info_get_xstats, DPDK) \
    X(INFO_LCORE, info_get_lcore, DPDK) \
    X(INFO_APP, info_get_app, DPDK) \

/* Deifne all supported platforms.
 * When a new platforms added, define like below.
 * By default, below macro will unmap all hardware dependent callback functions
 * whichever platform its running, only those callback would get registered in
 * thier platform dependent headers(include/vr_dpdk.h, include/vr_linux.h)
 * Eg: VR_INFO_HOST_MAP_<non-supported platform> */
#define VR_INFO_HOST_MAP_KERNEL(MSG, CB)
#define VR_INFO_HOST_MAP_DPDK(MSG, CB)

/* vr_info callback function arguments.
 * msg_req->inbuf      => vr_info provide some input to callback function(kind of filter).
 *              Eg: Incase for bondinfo, CLI wants to show a particular slave.
 * msg_req->inbuf_len  => Buffer length
 * msg_req->outbuf     => Callback function should allocate memory buffer and fill contents.
 * msg_req->outbuf_len => Callback function should provide Output buffer length.
 * msg_req->bufsz      => Optional: Send output buffer size from CLI
 * */
#define VR_INFO_ARGS vr_info_t *msg_req

#define VR_INFO_PASS_ARGS msg_req

#define VR_INFO_FAILED         -1
#define VR_INFO_MSG_TRUNC      -2

/* VR_INFO_MSG_BUF_TABLE would used to support multiple clients.
 * vRouter(server) can able to process max. of 64 clients.
 * Buf table id[0] is unused, so table size is 65 */
#define VR_INFO_MSG_BUF_TABLE  65
#define VR_INFO_MAX_CALLBACK   256

/* Default Output buffer size */
#define VR_INFO_DEF_BUF_SIZE 4096

/* We use X-Macro concept, based on elements in VR_INFO_REG(X), message will
 * get expanded.
 * For Eg:
 * #define VR_INFO_REG(X) \
 *     X(INFO_BOND, info_get_bond) => VR_MSG_INFO(INFO_BOND, info_get_bond) => INFO_BOND,
 *     X(INFO_LACP, info_get_lacp)    VR_MSG_INFO(INFO_LACP, info_get_lacp)    INFO_LACP,
 * */
#define VR_MSG_INFO(MSG, CB, ...) MSG,

/* vr_info callback functions are generic functions, this has to be mapped to
 * harware dependent API(eg: Kernel/DPDK) or independent API(eg: get nexthop info).
 * The below macro would get expanded to system generic function
 * Eg: int (*hos_vr_info_get_bond)(char **inbuf, int *inbuf_len, char **outbuf, int *outbuf_len)
 * */
#define VR_INFO_CB_REG(MSG, CB, ...) \
    int (*hos_vr_##CB)(VR_INFO_ARGS);

/* Declaring each callback function in "struct host_os" structure.
 * Callback function would be expanded like this below
 * Eg:
 * #define VR_INFO_REG(X) \
 *  X(INFO_BOND, info_get_bond) => VR_INFO_CB_REG(INFO_BOND, info_get_bond) =>
 *  int (*hos_vr_info_get_bond)(VR_INFO_ARGS);
 *  X(INFO_LACP, info_get_lacp) => VR_INFO_CB_REG(INFO_LACP, info_get_lacp) =>
 *  int (*hos_vr_info_get_lacp)(VR_INFO_ARGS);
 * */
#define FOREACH_VR_INFO_CB_DECLARATION() \
    VR_INFO_REG(VR_INFO_CB_REG)

typedef enum vr_info_msg {
    INFO_START,
    VR_INFO_REG(VR_MSG_INFO)
    INFO_MAX,
} vr_info_msg_en;

/* vr_info structure used to send with/without input(inbuf) and retrieve output
 * buffer */
typedef struct vr_info {
    char *inbuf;
    char *outbuf;
    uint32_t outbuf_len;
    uint32_t inbuf_len;
    uint32_t bufsz;
} vr_info_t;

/* Declaration of vr_info callback function*/
typedef int (*vr_info_cb_fn)(VR_INFO_ARGS);

/* Structure for users callback registration */
struct vr_info_callback {
    vr_info_msg_en msginfo;
    vr_info_cb_fn cb_fn;
};

/* Structure for storing output buffer and len for each client */
struct vr_info_buff_table {
    char *buff;
    int buf_len;
};

#define VR_INFO_DEC() \
    int len = 0;

#define VR_INFO_BUF_INIT() \
    VR_INFO_DEC(); \
    if(msg_req->bufsz) { \
        msg_req->outbuf = vr_zalloc(msg_req->bufsz, VR_INFO_REQ_OBJECT); \
    } else { \
        msg_req->outbuf = vr_zalloc(VR_INFO_DEF_BUF_SIZE, VR_INFO_REQ_OBJECT); \
        msg_req->bufsz = VR_INFO_DEF_BUF_SIZE; \
    } \
    if(msg_req->outbuf == NULL) { \
        vr_printf("Buffer allocation failed\n"); \
        return VR_INFO_FAILED; \
    }

#define VI_PRINTF(...) \
{ \
    len = snprintf((msg_req->outbuf + msg_req->outbuf_len), \
            (msg_req->bufsz - msg_req->outbuf_len), __VA_ARGS__ ); \
    if(len < 0) {  \
        vr_printf("VrInfo: snprintf - Message copy failed at %d\n", \
                msg_req->outbuf_len); \
        return VR_INFO_FAILED; \
    } \
    if (len > (msg_req->bufsz - msg_req->outbuf_len)) { \
            vr_printf("VrInfo: Message copy to buffer failed at %d\n", \
                    msg_req->outbuf_len); \
            return VR_INFO_MSG_TRUNC; \
    } \
    msg_req->outbuf_len += len; \
}

/* Below macro would register each callback function in Users callback table */
#define FOREACH_VR_INFO_INIT(MSG, CB, ...) \
{ \
    if(!MSG && !vrouter_host->hos_vr_##CB) { \
        vr_printf("vrdump: Invalid value %d or Callback function %p\n", \
                MSG, vrouter_host->hos_vr_##CB); \
        return -EINVAL; \
    } \
 \
    /* Check msginfo is valid */ \
    if((MSG <= 0) && (MSG >= INFO_MAX)) { \
        vr_printf("vrdump: Invalid msginfo value %d \n", MSG); \
        return -EINVAL;  \
    } \
    users_cb_reg[i].msginfo = MSG; \
    users_cb_reg[i].cb_fn = vrouter_host->hos_vr_##CB; \
    i++; \
}

/* Registering callback before processing the vr_info client request */
/* Considering index 0 is unused so starting i=1*/
#define FOREACH_VR_INFO_CB_REG_INIT() \
    int i = 1; \
    VR_INFO_REG(FOREACH_VR_INFO_INIT)

#endif /* __VR_INFO_H__ */
