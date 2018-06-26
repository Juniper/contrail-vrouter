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

static PWIN_PACKET
WinPacketRawAllocateClone_Impl(PWIN_PACKET Packet)
{
    return NULL;
}
PWIN_PACKET (*WinPacketRawAllocateClone)(PWIN_PACKET Packet) = WinPacketRawAllocateClone_Impl;
