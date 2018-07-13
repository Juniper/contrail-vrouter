/*
 * fake_win_packet_raw.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_packet_raw.h"
#include "win_packet_impl.h"
#include "fake_win_packet.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

struct _WIN_PACKET_RAW {
    PWIN_PACKET_RAW Parent;
    long ChildRefCount;
    bool IsOwned;
};

struct _WIN_PACKET {
    WIN_PACKET_RAW Packet;
};

static PWIN_PACKET
Fake_WinPacketAllocate(bool IsOwned)
{
    PWIN_PACKET packet = test_calloc(1, sizeof(*packet));
    assert(packet != NULL);
    WinPacketToRawPacket(packet)->IsOwned = IsOwned;
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

PWIN_PACKET_RAW
WinPacketRawGetParentOf(PWIN_PACKET_RAW Packet)
{
    return Packet->Parent;
}

void
WinPacketRawSetParentOf(PWIN_PACKET_RAW Packet, PWIN_PACKET_RAW Parent)
{
    Packet->Parent = Parent;
}

long
WinPacketRawGetChildCountOf(PWIN_PACKET_RAW Packet)
{
    return Packet->ChildRefCount;
}

long
WinPacketRawIncrementChildCountOf(PWIN_PACKET_RAW Packet)
{
    return ++Packet->ChildRefCount;
}

long
WinPacketRawDecrementChildCountOf(PWIN_PACKET_RAW Packet)
{
    return --Packet->ChildRefCount;
}

static PWIN_PACKET_RAW
WinPacketRawAllocateClone_Impl(PWIN_PACKET_RAW Packet)
{
    PWIN_PACKET_RAW cloned = WinPacketToRawPacket(Fake_WinPacketAllocateOwned());
    return cloned;
}
PWIN_PACKET_RAW (*WinPacketRawAllocateClone_Callback)(PWIN_PACKET_RAW Packet) = WinPacketRawAllocateClone_Impl;

PWIN_PACKET_RAW
WinPacketRawAllocateClone(PWIN_PACKET_RAW Packet)
{
    return WinPacketRawAllocateClone_Callback(Packet);
}

static void
WinPacketRawFreeClone_Impl(PWIN_PACKET_RAW Packet)
{
    Fake_WinPacketFree((PWIN_PACKET)Packet);
}
void (*WinPacketRawFreeClone_Callback)(PWIN_PACKET_RAW Packet) = WinPacketRawFreeClone_Impl;

void
WinPacketRawFreeClone(PWIN_PACKET_RAW Packet)
{
    WinPacketRawFreeClone_Callback(Packet);
}

bool
WinPacketRawIsOwned(PWIN_PACKET_RAW Packet)
{
    return Packet->IsOwned;
}

bool
WinPacketRawIsCloned(PWIN_PACKET_RAW Packet)
{
    return Packet->Parent != NULL;
}

static void
WinPacketRawComplete_Impl(PWIN_PACKET_RAW Packet)
{
    Fake_WinPacketFree((PWIN_PACKET)Packet);
}
void (*WinPacketRawComplete_Callback)(PWIN_PACKET_RAW Packet) = WinPacketRawComplete_Impl;

void
WinPacketRawComplete(PWIN_PACKET_RAW Packet)
{
    WinPacketRawComplete_Callback(Packet);
}

static void
WinPacketRawFreeCreated_Impl(PWIN_PACKET_RAW Packet)
{
    Fake_WinPacketFree((PWIN_PACKET)Packet);
}
void (*WinPacketRawFreeCreated_Callback)(PWIN_PACKET_RAW Packet) = WinPacketRawFreeCreated_Impl;

void
WinPacketRawFreeCreated(PWIN_PACKET_RAW Packet)
{
    WinPacketRawFreeCreated_Callback(Packet);
}
