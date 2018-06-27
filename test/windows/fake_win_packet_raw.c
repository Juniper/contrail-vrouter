/*
 * fake_win_packet_raw.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "fake_win_packet.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

struct _WIN_PACKET {
    PWIN_PACKET Parent;
    long ChildRefCount;
    bool IsOwned;
};

static PWIN_PACKET
Fake_WinPacketAllocate(bool IsOwned)
{
    PWIN_PACKET packet = test_calloc(1, sizeof(*packet));
    assert(packet != NULL);
    packet->IsOwned = IsOwned;
    return packet;
}

PWIN_PACKET
Fake_WinPacketAllocateOwned()
{
    return Fake_WinPacketAllocate(true);
}

PWIN_PACKET
Fake_WinPacketAllocateNonOwned()
{
    return Fake_WinPacketAllocate(false);
}

void
Fake_WinPacketFree(PWIN_PACKET Packet)
{
    test_free(Packet);
}

PWIN_PACKET
WinPacketRawGetParentOf(PWIN_PACKET Packet)
{
    return Packet->Parent;
}

void
WinPacketRawSetParentOf(PWIN_PACKET Packet, PWIN_PACKET Parent)
{
    Packet->Parent = Parent;
}

long
WinPacketRawGetChildCountOf(PWIN_PACKET Packet)
{
    return Packet->ChildRefCount;
}

long
WinPacketRawIncrementChildCountOf(PWIN_PACKET Packet)
{
    return ++Packet->ChildRefCount;
}

long
WinPacketRawDecrementChildCountOf(PWIN_PACKET Packet)
{
    return --Packet->ChildRefCount;
}

static PWIN_PACKET
WinPacketRawAllocateClone_Impl(PWIN_PACKET Packet)
{
    return Fake_WinPacketAllocateOwned();
}
PWIN_PACKET (*WinPacketRawAllocateClone_Callback)(PWIN_PACKET Packet) = WinPacketRawAllocateClone_Impl;

PWIN_PACKET
WinPacketRawAllocateClone(PWIN_PACKET Packet)
{
    return WinPacketRawAllocateClone_Callback(Packet);
}

static void
WinPacketRawFreeClone_Impl(PWIN_PACKET Packet)
{
    Fake_WinPacketFree(Packet);
}
void (*WinPacketRawFreeClone_Callback)(PWIN_PACKET Packet) = WinPacketRawFreeClone_Impl;

void
WinPacketRawFreeClone(PWIN_PACKET Packet)
{
    WinPacketRawFreeClone_Callback(Packet);
}

bool
WinPacketRawIsOwned(PWIN_PACKET Packet)
{
    return Packet->IsOwned;
}

bool
WinPacketRawIsCloned(PWIN_PACKET Packet)
{
    return Packet->Parent != NULL;
}

static void
WinPacketRawComplete_Impl(PWIN_PACKET Packet)
{
    Fake_WinPacketFree(Packet);
}
void (*WinPacketRawComplete_Callback)(PWIN_PACKET Packet) = WinPacketRawComplete_Impl;

void
WinPacketRawComplete(PWIN_PACKET Packet)
{
    WinPacketRawComplete_Callback(Packet);
}

static void
WinPacketRawFreeCreated_Impl(PWIN_PACKET Packet)
{
    Fake_WinPacketFree(Packet);
}
void (*WinPacketRawFreeCreated_Callback)(PWIN_PACKET Packet) = WinPacketRawFreeCreated_Impl;

void
WinPacketRawFreeCreated(PWIN_PACKET Packet)
{
    WinPacketRawFreeCreated_Callback(Packet);
}

void
WinRawFree(void *buffer) {
    test_free(buffer);
}
