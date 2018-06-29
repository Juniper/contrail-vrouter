/*
 * win_packet.c -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_packet.h"

extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);

#define WinAssert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);

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

static BOOL
WinPacketIsCloned(PWIN_PACKET Packet)
{
    return WinPacketRawGetParentOf(Packet) != NULL;
}

VOID
WinPacketFreeClonedPreservingParent(PWIN_PACKET Packet)
{
    PWIN_PACKET parent = WinPacketRawGetParentOf(Packet);

    WinPacketRawDecrementChildCountOf(parent);
    WinPacketRawFreeClone(Packet);
}

static VOID
WinPacketFreeClonedRecurvise(PWIN_PACKET Packet)
{
    PWIN_PACKET parent = WinPacketRawGetParentOf(Packet);

    WinPacketRawFreeClone(Packet);

    if (WinPacketRawDecrementChildCountOf(parent) == 0) {
        WinPacketFree(parent);
    }
}

VOID
WinPacketFree(PWIN_PACKET Packet)
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
