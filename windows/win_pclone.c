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
        WinPacketFreeClonedPreservingParent(leftWinPkt);
        return NULL;
    }

    return NULL;
}
