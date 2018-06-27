/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_packet.h"
#include "win_packet.h"

struct vr_packet *
win_pclone(struct vr_packet *VrPkt)
{
    if (VrPkt == NULL) {
        return NULL;
    }

    PWIN_PACKET leftWinPkt = WinPacketClone(GetWinPacketFromVrPacket(VrPkt));
    if (leftWinPkt == NULL) {
        return NULL;
    }

    PWIN_PACKET rightWinPkt = WinPacketClone(GetWinPacketFromVrPacket(VrPkt));
    if (rightWinPkt == NULL) {
        goto cleanup_left_pkt;
    }

    PVR_PACKET_WRAPPER rightPkt = NULL; // TODO
    if (rightPkt == NULL) {
        goto cleanup_both_pkts;
    }

    // TODO

cleanup_both_pkts:
    WinPacketFreeClonedPreservingParent(rightWinPkt);

cleanup_left_pkt:
    WinPacketFreeClonedPreservingParent(leftWinPkt);

    return NULL;
}
