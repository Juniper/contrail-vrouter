/*
 * win_packet.c -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_packet.h"
#include "win_packet_impl.h"
#include "win_packet_raw.h"

#include "win_assert.h"

static void WinPacketFreeRecursiveImpl(PWIN_PACKET_RAW RawPacket);

static inline PWIN_PACKET
WinPacketFromRawPacket(PWIN_PACKET_RAW Packet)
{
    return (PWIN_PACKET)Packet;
}

PWIN_PACKET
WinPacketClone(PWIN_PACKET Packet)
{
    PWIN_PACKET_RAW rawPacket = WinPacketToRawPacket(Packet);
    PWIN_PACKET_RAW rawCloned = WinPacketRawAllocateClone(rawPacket);
    if (rawCloned == NULL) {
        return NULL;
    }

    WinPacketRawSetParentOf(rawCloned, rawPacket);
    WinPacketRawIncrementChildCountOf(rawPacket);

    return WinPacketFromRawPacket(rawCloned);
}

static bool
WinPacketIsCloned(PWIN_PACKET_RAW RawPacket)
{
    return WinPacketRawGetParentOf(RawPacket) != NULL;
}

void
WinPacketFreeClonedPreservingParent(PWIN_PACKET Packet)
{
    PWIN_PACKET_RAW rawPacket = WinPacketToRawPacket(Packet);
    PWIN_PACKET_RAW rawParent = WinPacketRawGetParentOf(rawPacket);

    WinPacketRawDecrementChildCountOf(rawParent);
    WinPacketRawFreeClone(rawPacket);
}

static void
WinPacketFreeClonedRecurvise(PWIN_PACKET_RAW RawPacket)
{
    PWIN_PACKET_RAW rawParent = WinPacketRawGetParentOf(RawPacket);

    WinPacketRawFreeClone(RawPacket);

    if (WinPacketRawDecrementChildCountOf(rawParent) == 0) {
        WinPacketFreeRecursiveImpl(rawParent);
    }
}

static void
WinPacketFreeRecursiveImpl(PWIN_PACKET_RAW RawPacket)
{
    WinAssert(WinPacketRawGetChildCountOf(RawPacket) == 0);

    if (WinPacketRawIsOwned(RawPacket)) {
        if (WinPacketIsCloned(RawPacket)) {
            WinPacketFreeClonedRecurvise(RawPacket);
        } else {
            WinPacketRawFreeCreated(RawPacket);
        }
    } else {
        WinPacketRawComplete(RawPacket);
    }
}

void
WinPacketFreeRecursive(PWIN_PACKET Packet)
{
    PWIN_PACKET_RAW rawPacket = WinPacketToRawPacket(Packet);
    WinPacketFreeRecursiveImpl(rawPacket);
}
