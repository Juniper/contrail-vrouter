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
    X(INFO_BOND, info_get_bond)

/* vr_info callback function arguments.
 * inbuf      -> vr_info provide some input to callback function(kind of filter).
 *              Eg: Incase for bondinfo, CLI wants to show a particular slave.
 * inbuf_len  -> Buffer length
 * outbuf     -> Callback function should allocate memory buffer and fill contents.
 * outbuf_len -> Callback function should provide Output buffer length.
 * */
#define VR_INFO_ARGS char **inbuf, int *inbuf_len, char **outbuf, int *outbuf_len, int outbufsz

#define VR_INFO_FAILED         -1

/* VR_INFO_MSG_BUF_TABLE would used to support multiple clients.
 * vRouter(server) can able to process max. of 64 clients.
 * */
#define VR_INFO_MSG_BUF_TABLE  64
#define VR_INFO_MAX_CALLBACK   256

/* We use X-Macro concept, based on elements in VR_INFO_REG(X), message will
 * get expanded.
 * For Eg:
 * #define VR_INFO_REG(X) \
 *     X(INFO_BOND, info_get_bond) => VR_MSG_INFO(INFO_BOND, info_get_bond) => INFO_BOND,
 *     X(INFO_LACP, info_get_lacp)    VR_MSG_INFO(INFO_LACP, info_get_lacp)    INFO_LACP,
 * */
#define VR_MSG_INFO(MSG, CB) MSG,

/* vr_info callback functions are generic functions, this has to be mapped to
 * harware dependent API(eg: Kernel/DPDK) or independent API(eg: get nexthop info).
 * The below macro would get expanded to system generic function
 * Eg: int (*hos_vr_info_get_bond)(char **inbuf, int *inbuf_len, char **outbuf, int *outbuf_len)
 * */
#define VR_INFO_CB_REG(MSG, CB) \
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

/* Declaration of vr_info callback function*/
typedef int (*vr_info_cb_fn)(VR_INFO_ARGS);

/* vr_info structure used to send with/without input(inbuf) and retrieve output
 * buffer */
typedef struct vr_info {
    char *inbuf;
    char *outbuf;
    uint32_t outbuf_len;
    uint32_t inbuf_len;
} vr_info_t;

/* Structure for users callback registration */
struct vr_info_callback {
    vr_info_msg_en msginfo;
    vr_info_cb_fn cb_fn;
};

/* Below macro would register each callback function in Users callback table */
#define FOREACH_VR_INFO_INIT(MSG, CB) \
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
#define FOREACH_VR_INFO_CB_REG_INIT() \
    int i = 0; \
    VR_INFO_REG(FOREACH_VR_INFO_INIT)

#endif /* __VR_INFO_H__ */
