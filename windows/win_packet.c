/*
 * win_packet.c -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_packet.h"

#include "win_assert.h"

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

static bool
WinPacketIsCloned(PWIN_PACKET Packet)
{
    return WinPacketRawGetParentOf(Packet) != NULL;
}

void
WinPacketFreeClonedPreservingParent(PWIN_PACKET Packet)
{
    PWIN_PACKET parent = WinPacketRawGetParentOf(Packet);

    WinPacketRawDecrementChildCountOf(parent);
    WinPacketRawFreeClone(Packet);
}

static void
WinPacketFreeClonedRecurvise(PWIN_PACKET Packet)
{
    PWIN_PACKET parent = WinPacketRawGetParentOf(Packet);

    WinPacketRawFreeClone(Packet);

    if (WinPacketRawDecrementChildCountOf(parent) == 0) {
        WinPacketFreeRecursive(parent);
    }
}

void
WinPacketFreeRecursive(PWIN_PACKET Packet)
{
    WinAssert(WinPacketRawGetChildCountOf(Packet) == 0);

    if (WinPacketRawIsOwned(Packet)) {
        if (WinPacketIsCloned(Packet)) {
            WinPacketFreeClonedRecurvise(Packet);
        } else {
            WinPacketRawFreeCreated(Packet);
        }
    } else {
        WinPacketRawComplete(Packet);
    }
}
