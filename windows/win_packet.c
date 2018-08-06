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

/* NOTICE: This cast is safe to perform only if WinPacket contains single SubPacket */
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
WinPacketFreeMultiFragmentRecursive(PWIN_PACKET_RAW RawPacket)
{
    PWIN_PACKET_RAW rawParent = WinPacketRawGetParentOf(RawPacket);

    WinPacketRawFreeMultiFragment(RawPacket);

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
            if (WinPacketRawIsMultiFragment(RawPacket)) {
                WinPacketFreeMultiFragmentRecursive(RawPacket);
            } else {
                WinPacketFreeClonedRecurvise(RawPacket);
            }
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

static PWIN_PACKET_LIST
WinPacketSplitMultiPacketWithSingleSubPacket(PWIN_PACKET_RAW RawMultiPacket)
{
    PWIN_PACKET_LIST element = WinPacketListRawAllocateElement();
    if (element == NULL) {
        return NULL;
    }

    element->WinPacket = WinPacketFromRawPacket(RawMultiPacket);
    return element;
}

/*
 * Splits NBL with multiple NBs (WinMultiPacket) into list of NBLs,
 * in which each NBL has a single NB (WinPackets).
 *
 * The original NBL is set as a parent and left intact.
 * The returned value is a list of new NBLs (WinPacketList).
 */
static PWIN_PACKET_LIST
WinPacketSplitMultiPacketWithMultipleSubPackets(PWIN_PACKET_RAW RawMultiPacket)
{
    PWIN_SUB_PACKET firstSub = WinPacketRawGetFirstSubPacket(RawMultiPacket);
    PWIN_PACKET_LIST clonedWinPacketList = NULL;
    PWIN_PACKET_LIST *pNextElement = &clonedWinPacketList;
    PWIN_SUB_PACKET nextSub = NULL;

    for (PWIN_SUB_PACKET sub = firstSub; sub != NULL; sub = nextSub) {
        WinPacketRawSetFirstSubPacket(RawMultiPacket, sub);
        nextSub = WinSubPacketRawGetNext(sub);
        WinSubPacketRawSetNext(sub, NULL);

        PWIN_PACKET clonedPacket = WinPacketClone(WinPacketFromRawPacket(RawMultiPacket));

        WinSubPacketRawSetNext(sub, nextSub);

        if (clonedPacket == NULL) {
            goto cleanup;
        }

        *pNextElement = WinPacketListRawAllocateElement();
        if (*pNextElement == NULL) {
            WinPacketFreeClonedPreservingParent(clonedPacket);
            goto cleanup;
        }

        (*pNextElement)->WinPacket = clonedPacket;
        pNextElement = &(*pNextElement)->Next;
    }

    WinPacketRawSetFirstSubPacket(RawMultiPacket, firstSub);

    return clonedWinPacketList;

cleanup:
    WinPacketRawSetFirstSubPacket(RawMultiPacket, firstSub);

    PWIN_PACKET_LIST nextListElement = NULL;
    for (PWIN_PACKET_LIST clonedListElement = clonedWinPacketList; clonedListElement != NULL; clonedListElement = nextListElement) {
        nextListElement = clonedListElement->Next;
        WinPacketFreeClonedPreservingParent(clonedListElement->WinPacket);
        WinPacketListRawFreeElement(clonedListElement);
    }

    return NULL;
}

PWIN_PACKET_LIST
WinPacketSplitMultiPacket(PWIN_MULTI_PACKET WinMultiPacket)
{
    PWIN_PACKET_RAW rawPacket = WinMultiPacketToRawPacket(WinMultiPacket);
    PWIN_SUB_PACKET firstSub = WinPacketRawGetFirstSubPacket(rawPacket);
    if (firstSub == NULL) {
        return NULL;
    }

    if (WinSubPacketRawGetNext(firstSub) == NULL) {
        return WinPacketSplitMultiPacketWithSingleSubPacket(rawPacket);
    }

    return WinPacketSplitMultiPacketWithMultipleSubPackets(rawPacket);
}
