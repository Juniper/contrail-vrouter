/*
 * vr_dpdk_offloads.h -- dpdk callbacks for datapath flow offloads management
 *
 * Copyright 2018 Mellanox Technologies, Ltd
 */
#ifndef __VR_DPDK_OFFLOADS_H__
#define __VR_DPDK_OFFLOADS_H__

#include "vr_offloads.h"
#include "vr_dpdk.h"

int dpdk_offload_flow_destroy(struct vr_offload_flow *oflow);

int dpdk_offload_flow_create(struct vr_offload_flow *oflow);

void dpdk_offload_prepare(struct vr_packet *pkt, struct vr_forwarding_md *fmd);

static inline void
dpdk_offload_flow_burst_prefetch(struct rte_mbuf *pkts[VR_DPDK_RX_BURST_SZ],
                                 struct vr_offload_flow *oflows[VR_DPDK_RX_BURST_SZ],
                                 uint32_t nb_pkts)
{
    struct vr_offload_flow **oflow = &oflows[0];
    int i;

    for (i = 0; i < nb_pkts; i++, oflow++) {
        if (pkts[i]->ol_flags & PKT_RX_FDIR_ID) {
            *oflow = vr_offloads_flow_get(pkts[i]->hash.fdir.hi);
           if (*oflow)
               rte_prefetch0(*oflow);
       } else
           *oflow = NULL;
    }
}

static inline void
vr_dpdk_offloads_flow_prefetch(struct vr_offload_flow *oflow)
{
    rte_prefetch0(oflow->fe);
    rte_prefetch0((char *)oflow->fe + RTE_CACHE_LINE_SIZE);
    rte_prefetch0(oflow->nh);
    rte_prefetch0((char *)oflow->nh + RTE_CACHE_LINE_SIZE);
}

#endif /* __VR_DPDK_OFFLOADS_H__ */
