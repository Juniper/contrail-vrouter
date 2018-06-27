/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_packet.h"
#include "win_packet.h"
#include "win_assert.h"


void
win_pfree(struct vr_packet *pkt, unsigned short reason)
{
    WinAssert(pkt != NULL);

    //TODO: Test with fake vrouter
    // struct vrouter *router = vrouter_get(0);
    // unsigned int cpu = pkt->vp_cpu;

    // if (router)
    //     ((uint64_t *)(router->vr_pdrop_stats[cpu]))[reason]++;

    PVR_PACKET_WRAPPER wrapper = GetWrapperFromVrPacket(pkt);
    WinPacketFree(wrapper->WinPacket);
    
    WinRawFree(wrapper);
}