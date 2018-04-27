/*
 * vr_dpdk_lcore.h - header for DPDK lcore support functions.
 *
 *
 * Contributed by Semihalf
 * Copyright (c) 2015 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_DPDK_LCORE_H__
#define __VR_DPDK_LCORE_H__

/*
 * Lcore RX Ring Header Bits:
 *   63    - always set to 1
 *   62-47 - vif_idx (16 bit)
 *   46-15 - vif_gen (32 bit)
 *   14-0  - nb_pkts + 1 for the header (15 bit)
 */
#define LCORE_RX_RING_HEADER_OFF  63
#define LCORE_RX_RING_VIF_IDX_OFF 47
#define LCORE_RX_RING_VIF_IDX_MASK 0xFFFFU
#define LCORE_RX_RING_VIF_GEN_OFF 15
#define LCORE_RX_RING_VIF_GEN_MASK 0xFFFFFFFFU
#define LCORE_RX_RING_NB_PKTS_MASK 0x7fffU


#endif /* __VR_DPDK_LCORE_H__ */
