/*
 * fake_win_packet_raw.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_packet_raw.h"
#include "fake_win_packet.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

// In win_packet.c (not raw)
// struct _WIN_PACKET {
//     WIN_MULTI_PACKET packet;
// };

// struct _WIN_SUB_PACKET {
//     int data;
//     PWIN_SUB_PACKET Next;
// };

// struct _WIN_MULTI_PACKET {
//     PWIN_MULTI_PACKET Parent;
//     long ChildRefCount;
//     bool IsOwned;
//     PWIN_SUB_PACKET FirstSubPacket;
// };

struct _WIN_PACKET {
    PWIN_PACKET Parent;
    long ChildRefCount;
    bool IsOwned;
};

struct _WIN_SUB_PACKET {
    PWIN_PACKET Packet;
    PWIN_SUB_PACKET Next;
};

struct _WIN_MULTI_PACKET {
    PWIN_SUB_PACKET FirstSubPacket;
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

static void
Fake_WinMultiPacketAllocateSubPackets(PWIN_MULTI_PACKET Packet, size_t SubPacketsCount)
{
    PWIN_SUB_PACKET *localSubPackets = test_calloc(SubPacketsCount, sizeof(PWIN_SUB_PACKET));

    for (size_t i = 0; i < SubPacketsCount; ++i) {
        PWIN_SUB_PACKET subPacket = test_calloc(1, sizeof(*subPacket));

        localSubPackets[i] = subPacket;
        if (i != 0) {
            localSubPackets[i - 1]->Next = subPacket;
        }

        subPacket->Packet = Fake_WinPacketAllocateNonOwned();
    }

    Packet->FirstSubPacket = localSubPackets[0];

    test_free(localSubPackets);
}

PWIN_MULTI_PACKET
Fake_WinMultiPacketAllocateWithSubPackets(size_t SubPacketsCount)
{
    PWIN_MULTI_PACKET packet = test_calloc(1, sizeof(*packet));

    if (SubPacketsCount > 0) {
        Fake_WinMultiPacketAllocateSubPackets(packet, SubPacketsCount);
    }

    return packet;
}

static void Fake_WinSubPacketFreeRecursive(PWIN_SUB_PACKET SubPacket, bool FreeWinPackets)
{
    if (SubPacket != NULL) {
        Fake_WinSubPacketFreeRecursive(SubPacket->Next, FreeWinPackets);

        if (FreeWinPackets) {
            test_free(SubPacket->Packet);
        }

        test_free(SubPacket);
    }
}

void
Fake_WinMultiPacketFree(PWIN_MULTI_PACKET Packet, bool FreeWinPackets)
{
    Fake_WinSubPacketFreeRecursive(Packet->FirstSubPacket, FreeWinPackets);
    test_free(Packet);
}

PWIN_PACKET
Fake_WinSubPacketToWinPacket(PWIN_SUB_PACKET SubPacket)
{
    return SubPacket->Packet;
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

PWIN_PACKET
WinMultiPacketRawToWinPacket(PWIN_MULTI_PACKET MultiPacket)
{
    assert_null(MultiPacket->FirstSubPacket->Next);
    return MultiPacket->FirstSubPacket->Packet;
}

static PWIN_PACKET_LIST
WinPacketListRawAllocateElement_Impl()
{
    return test_calloc(1, sizeof(WIN_PACKET_LIST));
}
PWIN_PACKET_LIST (*WinPacketListRawAllocateElement_Callback)() = WinPacketListRawAllocateElement_Impl;

PWIN_PACKET_LIST
WinPacketListRawAllocateElement()
{
    return WinPacketListRawAllocateElement_Callback();
}

void
WinPacketListRawFreeElement(PWIN_PACKET_LIST List) {
    test_free(List);
}

void
Fake_WinPacketListRawFree(PWIN_PACKET_LIST List)
{
    if (List != NULL) {
        Fake_WinPacketListRawFree(List->Next);
        test_free(List->WinPacket);
        test_free(List);
    }
}

PWIN_SUB_PACKET
WinMultiPacketRawGetFirstSubPacket(PWIN_MULTI_PACKET MultiPacket)
{
    return MultiPacket->FirstSubPacket;
}

void
WinMultiPacketRawSetFirstSubPacket(PWIN_MULTI_PACKET MultiPacket, PWIN_SUB_PACKET SubPacket)
{
    MultiPacket->FirstSubPacket = SubPacket;
}

PWIN_SUB_PACKET
WinSubPacketRawGetNext(PWIN_SUB_PACKET SubPacket)
{
    return SubPacket->Next;
}

void
WinSubPacketRawSetNext(PWIN_SUB_PACKET SubPacket, PWIN_SUB_PACKET Next)
{
    SubPacket->Next = Next;
}
