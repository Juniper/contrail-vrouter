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

// `OwnsData` - if true, then buffer pointed to by `Data` pointer should be freed
// alongside _WIN_SUB_PACKET.
struct _WIN_SUB_PACKET {
    void *Data;
    bool  OwnsData;
    size_t Size;
    PWIN_SUB_PACKET Next;
};

struct _WIN_PACKET_RAW {
    PWIN_PACKET_RAW Parent;
    long ChildRefCount;
    bool IsOwned;
    bool IsMultiFragment;

    bool IsIpChecksumOffloaded;
    bool IsUdpChecksumOffloaded;
    bool IsSegmentationOffloaded;

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

    PWIN_SUB_PACKET subPacket = test_calloc(1, sizeof(*subPacket));
    assert(subPacket != NULL);
    WinPacketToRawPacket(packet)->FirstSubPacket = subPacket;

    return packet;
}

void
Fake_WinPacketRawSetOffloadInfo(PWIN_PACKET_RAW packet, bool IpChecksumOffload, bool UdpChecksumOffload, bool SegmentationOffload)
{
    packet->IsIpChecksumOffloaded = IpChecksumOffload;
    packet->IsUdpChecksumOffloaded = UdpChecksumOffload;
    packet->IsSegmentationOffloaded = SegmentationOffload;
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

static void Fake_WinSubPacketFreeRecursive(PWIN_SUB_PACKET SubPacket);

void
Fake_WinPacketFree(PWIN_PACKET Packet)
{
    PWIN_PACKET_RAW packet = WinPacketToRawPacket(Packet);

    if (packet->FirstSubPacket != NULL) {
        Fake_WinSubPacketFreeRecursive(packet->FirstSubPacket);
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
        subPacket->Data = test_calloc(1, 1);
        subPacket->OwnsData = true;
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
        if (SubPacket->Data != NULL && SubPacket->OwnsData) {
            test_free(SubPacket->Data);
        }
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

size_t
Fake_WinSubPacketGetDataSize(PWIN_SUB_PACKET SubPacket)
{
    return SubPacket->Size;
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
    return Packet->IsIpChecksumOffloaded;
}

BOOLEAN
WinPacketRawShouldTcpChecksumBeOffloaded(PWIN_PACKET_RAW Packet)
{
    return false;
}

BOOLEAN
WinPacketRawShouldUdpChecksumBeOffloaded(PWIN_PACKET_RAW Packet)
{
    return Packet->IsUdpChecksumOffloaded;
}

BOOLEAN
WinPacketRawShouldSegmentationBeOffloaded(PWIN_PACKET_RAW Packet)
{
    return Packet->IsSegmentationOffloaded;
}

VOID
WinPacketRawClearTcpChecksumOffloading(PWIN_PACKET_RAW Packet)
{
    // TODO: Really... clear it.
}

VOID
WinPacketRawClearUdpChecksumOffloading(PWIN_PACKET_RAW Packet)
{
    Packet->IsUdpChecksumOffloaded = false;
}

VOID
WinPacketRawClearChecksumOffloading(PWIN_PACKET_RAW Packet)
{
    Packet->IsIpChecksumOffloaded = false;
    WinPacketRawClearTcpChecksumOffloading(Packet);
    WinPacketRawClearUdpChecksumOffloading(Packet);
}

VOID
WinPacketRawClearSegmentationOffloading(PWIN_PACKET_RAW Packet)
{
    Packet->IsSegmentationOffloaded = false;
}

ULONG
WinSubPacketRawDataLength(PWIN_SUB_PACKET SubPacket)
{
    return SubPacket->Size;
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
    // TODO
    return 1300;
}

BOOLEAN
WinPacketRawCopyOutOfBandData(PWIN_PACKET_RAW Child, PWIN_PACKET_RAW Original)
{
    return true;
}

PWIN_PACKET_RAW WinPacketRawAllocateMultiFragment(
    PWIN_PACKET_RAW OriginalPkt, ULONG HeadersSize, ULONG MaxFragmentLen)
{
    PWIN_SUB_PACKET originalSubPkt = OriginalPkt->FirstSubPacket;
    assert(originalSubPkt->Next == NULL);

    uint8_t *data = originalSubPkt->Data;
    size_t dataSize = originalSubPkt->Size;

    uint8_t *payload = data + HeadersSize;
    size_t payloadSize = dataSize - HeadersSize;

    PWIN_PACKET fragmentedPacket = Fake_WinPacketAllocate(true);
    PWIN_PACKET_RAW rawFragmentedPacket = WinPacketToRawPacket(fragmentedPacket);
    PWIN_SUB_PACKET *subPacketPtr = &rawFragmentedPacket->FirstSubPacket;

    for (size_t payloadOffset = 0; payloadOffset < payloadSize; payloadOffset += MaxFragmentLen) {
        size_t fragmentPayloadSize =
            payloadOffset + MaxFragmentLen < payloadSize ?
                MaxFragmentLen : payloadSize - payloadOffset;

        size_t fragmentSize = fragmentPayloadSize + HeadersSize;

        uint8_t *buffer = test_calloc(fragmentSize, 1);
        memcpy(buffer + HeadersSize, payload + payloadOffset, fragmentPayloadSize);

        if (*subPacketPtr == NULL) {
            *subPacketPtr = test_calloc(1, sizeof(**subPacketPtr));
            assert(*subPacketPtr != NULL);
        }

        (*subPacketPtr)->Data = buffer;
        (*subPacketPtr)->OwnsData = true;
        (*subPacketPtr)->Size = fragmentSize;

        subPacketPtr = &(*subPacketPtr)->Next;
    }

    return rawFragmentedPacket;
}

VOID WinPacketRawFreeMultiFragmentWithoutFwdContext(PWIN_PACKET_RAW Packet)
{
    assert(false && "Not implemented");
}

VOID WinPacketRawAssertAllHeadersAreInFirstMDL(
    PWIN_PACKET_RAW Packet, ULONG HeadersSize)
{
}

VOID WinPacketRawCopyHeadersToSubPacket(
    PWIN_SUB_PACKET SubPkt, PWIN_PACKET_RAW OriginalPkt, ULONG HeadersSize)
{
    PWIN_SUB_PACKET originalSubPkt = OriginalPkt->FirstSubPacket;
    memcpy(SubPkt->Data, originalSubPkt->Data, HeadersSize);
}

PVOID WinSubPacketRawGetDataPtr(PWIN_SUB_PACKET SubPacket)
{
    return SubPacket->Data;
}

static PWIN_PACKET_RAW
WinPacketRawAllocateClone_Impl(PWIN_PACKET_RAW Packet)
{
    PWIN_PACKET_RAW cloned = WinPacketToRawPacket(Fake_WinPacketAllocateOwned());

    if (Packet->FirstSubPacket != NULL) {
        assert_null(Packet->FirstSubPacket->Next);
        *cloned->FirstSubPacket = *Packet->FirstSubPacket;
        cloned->FirstSubPacket->OwnsData = false;
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
Fake_WinPacketListRawFree(PWIN_PACKET_LIST List, bool OwnsPacket)
{
    if (List != NULL) {
        Fake_WinPacketListRawFree(List->Next, OwnsPacket);
        if (List->WinPacket != NULL) {
            // NOTE: We do not use Fake_WinPacketFree, because in fake implementation
            // cloning copies pointer values. On attempt to free MULTI_PACKET and WIN_PACKET_LIST
            // there is a double-free on this pointer.
            PWIN_PACKET packet = List->WinPacket;
            PWIN_PACKET_RAW rawPacket = WinPacketToRawPacket(packet);
            assert(rawPacket->FirstSubPacket->Next == NULL);
            if (OwnsPacket) {
                test_free(rawPacket->FirstSubPacket);
                test_free(rawPacket);
            }
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
