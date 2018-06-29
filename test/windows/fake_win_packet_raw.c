/*
 * fake_win_packet_raw.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "fake_win_packet.h"

#include <assert.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

struct _WIN_PACKET {
    PWIN_PACKET Parent;
    LONG ChildRefCount;
    BOOL IsOwned;
};

PWIN_PACKET
Fake_WinPacketAllocate()
{
    PWIN_PACKET packet = test_malloc(sizeof(*packet));
    assert(packet != NULL);
    memset(packet, 0, sizeof(*packet));
    return packet;
}

VOID
Fake_WinPacketFree(PWIN_PACKET Packet)
{
    test_free(Packet);
}

PWIN_PACKET
WinPacketRawGetParentOf(PWIN_PACKET Packet)
{
    return Packet->Parent;
}

VOID
WinPacketRawSetParentOf(PWIN_PACKET Packet, PWIN_PACKET Parent)
{
    Packet->Parent = Parent;
}

LONG
WinPacketRawGetChildCountOf(PWIN_PACKET Packet)
{
    return Packet->ChildRefCount;
}

VOID
WinPacketRawIncrementChildCountOf(PWIN_PACKET Packet)
{
    Packet->ChildRefCount++;
}

LONG
WinPacketRawDecrementChildCountOf(PWIN_PACKET Packet)
{
    return --Packet->ChildRefCount;
}

static PWIN_PACKET
WinPacketRawAllocateClone_Impl(PWIN_PACKET Packet)
{
    return Fake_WinPacketAllocate();
}
PWIN_PACKET (*WinPacketRawAllocateClone)(PWIN_PACKET Packet) = WinPacketRawAllocateClone_Impl;

VOID
WinPacketRawFreeClone(PWIN_PACKET Packet)
{
    Fake_WinPacketFree(Packet);
}

BOOL
WinPacketRawIsOwned(PWIN_PACKET Packet)
{
    return Packet->IsOwned;
}

BOOL
WinPacketRawIsCloned(PWIN_PACKET Packet)
{
    return Packet->Parent != NULL;
}

VOID
Fake_WinPacketSetIsOwned(PWIN_PACKET Packet, BOOL IsOwned)
{
    Packet->IsOwned = IsOwned;
}

static VOID
WinPacketRawComplete_Impl(PWIN_PACKET Packet)
{
    Fake_WinPacketFree(Packet);
}
VOID (*WinPacketRawComplete)(PWIN_PACKET Packet) = WinPacketRawComplete_Impl;

static VOID
WinPacketRawFreeCreated_Impl(PWIN_PACKET Packet)
{
    Fake_WinPacketFree(Packet);
}
VOID (*WinPacketRawFreeCreated)(PWIN_PACKET Packet) = WinPacketRawFreeCreated_Impl;
