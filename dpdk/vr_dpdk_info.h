/*
 * vr_dpdk_info.h - handles messages from Dpdkinfo CLI request.
 *
 * Copyright (c) 2020 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_DPDK_INFO_H__
#define __VR_DPDK_INFO_H__

#define VR_DPDK_INFO_DEF_BUF_SIZE 4096

#define DPDK_INFO_BUF_INIT() \
    int len = 0, pos = 0, bufsz = 0; \
    char *buff; \
    if(outbufsz) { \
        *outbuf = vr_zalloc(outbufsz, VR_INFO_REQ_OBJECT); \
        bufsz = outbufsz; \
    } \
    else { \
        *outbuf = vr_zalloc(VR_DPDK_INFO_DEF_BUF_SIZE, VR_INFO_REQ_OBJECT); \
        bufsz = VR_DPDK_INFO_DEF_BUF_SIZE; \
    } \
    buff = *outbuf; \
    if(*outbuf == NULL) { \
        RTE_LOG(ERR, VROUTER, "Buffer allocation failed"); \
        return VR_INFO_FAILED; \
    } \
    memset(buff, 0, (bufsz - 1)); \


#define DI_PRINTF(...) \
{ \
    len = snprintf((buff + pos), (bufsz - pos), __VA_ARGS__ ); \
    if(len < 0) {  \
        RTE_LOG(ERR, VROUTER, "DPDKInfo: snprintf - Message copy failed at %d\n", pos); \
        return -1; \
    } \
    if (len > (bufsz - pos)) { \
            RTE_LOG(ERR, VROUTER, "DPDKInfo: Message copy to buffer failed at %d\n", pos); \
            return -1; \
    } \
    pos += len; \
    *outbuf_len = pos; \
}\

#endif /* __VR_DPDK_INFO_H__ */

