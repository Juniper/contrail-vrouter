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

struct _WIN_SUB_PACKET {
    void *Data;
    size_t Size;
    PWIN_SUB_PACKET Next;
};

struct _WIN_PACKET_RAW {
    PWIN_PACKET_RAW Parent;
    long ChildRefCount;
    bool IsOwned;
    bool IsMultiFragment;

    bool IsUdpChecksumOffloaded;

    PWIN_SUB_PACKET FirstSubPacket;
};

struct _WIN_PACKET {
    WIN_PACKET_RAW Packet;
};

struct _WIN_MULTI_PACKET {
    WIN_PACKET_RAW Packet;
};

static PWIN_PACKET
Fake_WinPacketAllocate(bool IsOwned)
{
    PWIN_PACKET packet = test_calloc(1, sizeof(*packet));
    assert(packet != NULL);
    WinPacketToRawPacket(packet)->IsOwned = IsOwned;

    // TODO: This is temporary to make first test pass
    WinPacketToRawPacket(packet)->IsUdpChecksumOffloaded = true;

    PWIN_SUB_PACKET subPacket = test_calloc(1, sizeof(*subPacket));
    assert(subPacket != NULL);
    WinPacketToRawPacket(packet)->FirstSubPacket = subPacket;

    return packet;
}

PWIN_PACKET
Fake_WinPacketAllocateMultiFragment()
{
    PWIN_PACKET parent = Fake_WinPacketAllocateOwned();
    PWIN_PACKET cloned = WinPacketClone(parent);
    WinPacketToRawPacket(cloned)->IsMultiFragment = true;
    return cloned;
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
    PWIN_PACKET_RAW packet = WinPacketToRawPacket(Packet);

    if (packet->FirstSubPacket != NULL) {
        test_free(packet->FirstSubPacket);
    }

    test_free(Packet);
}

static void
Fake_WinMultiPacketAllocateSubPackets(PWIN_MULTI_PACKET Packet, size_t SubPacketsCount)
{
    PWIN_PACKET_RAW rawPacket = WinMultiPacketToRawPacket(Packet);
    PWIN_SUB_PACKET *localSubPackets = test_calloc(SubPacketsCount, sizeof(PWIN_SUB_PACKET));

    for (size_t i = 0; i < SubPacketsCount; ++i) {
        PWIN_SUB_PACKET subPacket = test_calloc(1, sizeof(*subPacket));

        localSubPackets[i] = subPacket;
        if (i != 0) {
            localSubPackets[i - 1]->Next = subPacket;
        }

        // In all tests using this function, we are checking for ptr
        // equality only, so we do not need any valid memory address here.
        subPacket->Data = (void *)(i + 1);
    }

    rawPacket->FirstSubPacket = localSubPackets[0];

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

static void
Fake_WinSubPacketFreeRecursive(PWIN_SUB_PACKET SubPacket)
{
    if (SubPacket != NULL) {
        Fake_WinSubPacketFreeRecursive(SubPacket->Next);
        test_free(SubPacket);
    }
}

void
Fake_WinMultiPacketFree(PWIN_MULTI_PACKET Packet)
{
    PWIN_PACKET_RAW rawPacket = WinMultiPacketToRawPacket(Packet);
    Fake_WinSubPacketFreeRecursive(rawPacket->FirstSubPacket);
    test_free(Packet);
}

void *
Fake_WinSubPacketGetData(PWIN_SUB_PACKET SubPacket)
{
    return SubPacket->Data;
}

void
Fake_WinSubPacketSetData(PWIN_SUB_PACKET SubPacket, void *Data, size_t Size)
{
    SubPacket->Data = Data;
    SubPacket->Size = Size;
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

BOOLEAN
WinPacketRawShouldIpChecksumBeOffloaded(PWIN_PACKET_RAW Packet)
{
    return true;
}

BOOLEAN
WinPacketRawShouldTcpChecksumBeOffloaded(PWIN_PACKET_RAW Packet)
{
    return false;
}

VOID
WinPacketRawClearTcpChecksumFlags(PWIN_PACKET_RAW Packet)
{
    // TODO: Really... clear it.
}

BOOLEAN
WinPacketRawShouldUdpChecksumBeOffloaded(PWIN_PACKET_RAW Packet)
{
    return Packet->IsUdpChecksumOffloaded;
}

VOID
WinPacketRawClearUdpChecksumFlags(PWIN_PACKET_RAW Packet)
{
    Packet->IsUdpChecksumOffloaded = false;
}

VOID
WinPacketRawClearChecksumInfo(PWIN_PACKET_RAW Packet)
{
    assert(false && "Not implemented");
}

ULONG
WinSubPacketRawDataLength(PWIN_SUB_PACKET SubPacket)
{
    assert(false && "Not implemented");
    return 0;
}

ULONG
WinPacketRawDataLength(PWIN_PACKET_RAW Packet)
{
    PWIN_SUB_PACKET subPkt = WinPacketRawGetFirstSubPacket(Packet);
    return subPkt->Size;
}

PVOID
WinSubPacketRawGetDataBuffer(PWIN_SUB_PACKET SubPacket, PVOID Buffer, ULONG BufferSize)
{
    assert(SubPacket->Size == BufferSize);
    return SubPacket->Data;
}

PVOID
WinPacketRawGetDataBuffer(
    PWIN_PACKET_RAW Packet, PVOID Buffer, ULONG BufferSize)
{
    PWIN_SUB_PACKET subPkt = WinPacketRawGetFirstSubPacket(Packet);
    return WinSubPacketRawGetDataBuffer(subPkt, Buffer, BufferSize);
}

PVOID
WinPacketRawDataAtOffset(PWIN_PACKET_RAW Packet, UINT16 Offset)
{
    PWIN_SUB_PACKET subPkt = WinPacketRawGetFirstSubPacket(Packet);
    PUINT8 p = subPkt->Data;
    return p + Offset;
}

ULONG
WinPacketRawGetMSS(PWIN_PACKET_RAW Packet)
{
    assert(false && "Not implemented");
    return 0;
}

BOOLEAN
WinPacketRawCopyOutOfBandData(PWIN_PACKET_RAW Child, PWIN_PACKET_RAW Original)
{
    assert(false && "Not implemented");
    return false;
}

PWIN_PACKET_RAW WinPacketRawAllocateMultiFragment(
    PWIN_PACKET_RAW OriginalPkt, ULONG HeadersSize, ULONG MaxFragmentLen)
{
    assert(false && "Not implemented");
    return NULL;
}

VOID WinPacketRawFreeMultiFragmentWithoutFwdContext(PWIN_PACKET_RAW Packet)
{
    assert(false && "Not implemented");
}

VOID WinPacketRawAssertAllHeadersAreInFirstMDL(
    PWIN_PACKET_RAW Packet, ULONG HeadersSize)
{
    assert(false && "Not implemented");
}

VOID WinPacketRawCopyHeadersToSubPacket(
    PWIN_SUB_PACKET SubPkt, PWIN_PACKET_RAW OriginalPkt, ULONG HeadersSize)
{
    assert(false && "Not implemented");
}

PVOID WinSubPacketRawGetDataPtr(PWIN_SUB_PACKET SubPacket)
{
    assert(false && "Not implemented");
    return NULL;
}

static PWIN_PACKET_RAW
WinPacketRawAllocateClone_Impl(PWIN_PACKET_RAW Packet)
{
    PWIN_PACKET_RAW cloned = WinPacketToRawPacket(Fake_WinPacketAllocateOwned());

    if (Packet->FirstSubPacket != NULL) {
        assert_null(Packet->FirstSubPacket->Next);
        *cloned->FirstSubPacket = *Packet->FirstSubPacket;
    }

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

void
WinPacketRawFreeMultiFragment(PWIN_PACKET_RAW Packet)
{
    WinPacketRawFreeMultiFragment_Callback(Packet);
}

BOOLEAN
WinPacketRawIsOwned(PWIN_PACKET_RAW Packet)
{
    return Packet->IsOwned;
}

BOOLEAN
WinPacketRawIsCloned(PWIN_PACKET_RAW Packet)
{
    return Packet->Parent != NULL;
}

BOOLEAN
WinPacketRawIsMultiFragment(PWIN_PACKET_RAW Packet)
{
    return Packet->IsMultiFragment;
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

void
WinPacketRawFreeMultiFragment_Impl(PWIN_PACKET_RAW Packet)
{
    Fake_WinPacketFree((PWIN_PACKET)Packet);
}
void (*WinPacketRawFreeMultiFragment_Callback)(PWIN_PACKET_RAW Packet) = WinPacketRawFreeMultiFragment_Impl;

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
WinPacketListRawFreeElement(PWIN_PACKET_LIST Element) {
    test_free(Element);
}

void
Fake_WinPacketListRawFree(PWIN_PACKET_LIST List)
{
    if (List != NULL) {
        Fake_WinPacketListRawFree(List->Next);
        if (List->WinPacket != NULL) {
            Fake_WinPacketFree(List->WinPacket);
        }
        WinPacketListRawFreeElement(List);
    }
}

PWIN_SUB_PACKET
WinPacketRawGetFirstSubPacket(PWIN_PACKET_RAW Packet)
{
    return Packet->FirstSubPacket;
}

void
WinPacketRawSetFirstSubPacket(PWIN_PACKET_RAW Packet, PWIN_SUB_PACKET SubPacket)
{
    Packet->FirstSubPacket = SubPacket;
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
