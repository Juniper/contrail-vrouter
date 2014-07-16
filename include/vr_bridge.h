/*
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_BRIDGE_H__
#define __VR_BRIDGE_H__

#include "vr_defs.h"
#include "vrouter.h"

#define VR_MAC_COPY(dst, src) { \
    ((uint16_t *)(dst))[0] = ((uint16_t *)(src))[0]; \
    ((uint16_t *)(dst))[1] = ((uint16_t *)(src))[1]; \
    ((uint16_t *)(dst))[2] = ((uint16_t *)(src))[2]; \
}

#define VR_ETH_COPY(dst, src) { \
    VR_MAC_COPY((unsigned char *)(dst), (unsigned char *)(src)); \
    VR_MAC_COPY(((unsigned char *)(dst) + 6), ((unsigned char *)(src) + 6)); \
    ((uint16_t *)(dst))[6] = ((uint16_t *)(src))[6]; \
}

#define VR_MAC_CMP(dst, src)  \
     ((((uint16_t *)dst)[0] == ((uint16_t *)src)[0]) && \
     (((uint16_t *)dst)[1] == ((uint16_t *)src)[1]) &&  \
     (((uint16_t *)dst)[2] == ((uint16_t *)src)[2]))  \

#define IS_MAC_ZERO(dst) \
     ((((uint16_t *)dst)[0] == 0) && \
     (((uint16_t *)dst)[1] == 0) &&  \
     (((uint16_t *)dst)[2] == 0))  \

#define IS_MAC_BCAST(dst) \
     ((((uint16_t *)dst)[0] == 0xffff) && \
     (((uint16_t *)dst)[1] == 0xffff) &&  \
     (((uint16_t *)dst)[2] == 0xffff))  \

#define IS_MAC_BMCAST(dst) \
     (((uint8_t *)dst)[0]& 0x1) 

#define VR_BE_FLAG_VALID                 0x01
#define VR_BE_FLAG_LABEL_VALID           0x02


unsigned int
vr_bridge_input(struct vrouter *, unsigned short , struct vr_packet *, 
                            struct vr_forwarding_md *);
#endif
