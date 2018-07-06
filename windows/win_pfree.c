/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_packet.h"
#include "win_packet.h"
#include "win_assert.h"
#include "win_memory.h"

// TODO: This function is defined in:
//       - for unit tests - fake_vrouter.c
//       - production code - vr_host.c
//       This is workaround for compiling vrouter.c into unit tests.
extern void win_update_drop_stats(struct vr_packet *pkt, unsigned short reason);

void
win_pfree(struct vr_packet *pkt, unsigned short reason)
{
    WinAssert(pkt != NULL);

    //TODO: Test with fake vrouter
    win_update_drop_stats(pkt, reason);

    PVR_PACKET_WRAPPER wrapper = GetWrapperFromVrPacket(pkt);
    WinPacketFreeRecursive(wrapper->WinPacket);

    WinRawFree(wrapper);
}
