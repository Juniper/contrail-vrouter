/*
 * win_packet.c -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_packet.h"

PWIN_PACKET
WinPacketClone(PWIN_PACKET Packet)
{
    PWIN_PACKET cloned = WinPacketRawAllocateClone(Packet);
    if (cloned == NULL) {
        return NULL;
    }

    WinPacketRawSetParentOf(cloned, Packet);
    WinPacketRawIncrementChildCountOf(Packet);

    return cloned;
}
