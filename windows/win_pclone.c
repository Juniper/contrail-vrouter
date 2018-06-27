/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_packet.h"
#include "win_packet.h"
#include "win_memory.h"
#include "win_assert.h"

struct vr_packet *
win_pclone(struct vr_packet *VrPkt)
{
    //TODO: For testing purpose we will keep assert for now.
    //However, after fragmentation we should delete the assert, because
    //we do not know if dpcore can call this function with NULL pointer.
    WinAssert(VrPkt != NULL);
    if (VrPkt == NULL) {
        return NULL;
    }

    PVR_PACKET_WRAPPER leftPkt = GetWrapperFromVrPacket(VrPkt);

    PWIN_PACKET leftWinPkt = WinPacketClone(leftPkt->WinPacket);
    if (leftWinPkt == NULL) {
        return NULL;
    }

    PWIN_PACKET rightWinPkt = WinPacketClone(leftPkt->WinPacket);
    if (rightWinPkt == NULL) {
        goto cleanup_left_pkt;
    }

    PVR_PACKET_WRAPPER rightPkt = WinRawAllocate(sizeof(*rightPkt));
    if (rightPkt == NULL) {
        goto cleanup_both_pkts;
    }

    rightPkt->WinPacket = rightWinPkt;
    rightPkt->VrPacket = *VrPkt;

    leftPkt->WinPacket = leftWinPkt;

    return &rightPkt->VrPacket;

cleanup_both_pkts:
    WinPacketFreeClonedPreservingParent(rightWinPkt);

cleanup_left_pkt:
    WinPacketFreeClonedPreservingParent(leftWinPkt);

    return NULL;
}
