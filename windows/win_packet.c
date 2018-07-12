/*
 * win_packet.c -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_packet.h"
#include "win_packet_raw.h"

#include "win_assert.h"

static inline PWIN_PACKET
WinPacketFromRawPacket(PWIN_PACKET_RAW Packet)
{
    return (PWIN_PACKET)Packet;
}

PWIN_PACKET
WinPacketClone(PWIN_PACKET Packet)
{
    PWIN_PACKET_RAW packet = WinPacketToRawPacket(Packet);
    PWIN_PACKET_RAW cloned = WinPacketRawAllocateClone(packet);
    if (cloned == NULL) {
        return NULL;
    }

    WinPacketRawSetParentOf(cloned, packet);
    WinPacketRawIncrementChildCountOf(packet);

    return WinPacketFromRawPacket(cloned);
}

static bool
WinPacketIsCloned(PWIN_PACKET Packet)
{
    PWIN_PACKET_RAW packet = WinPacketToRawPacket(Packet);
    return WinPacketRawGetParentOf(packet) != NULL;
}

void
WinPacketFreeClonedPreservingParent(PWIN_PACKET Packet)
{
    PWIN_PACKET_RAW packet = WinPacketToRawPacket(Packet);
    PWIN_PACKET_RAW parent = WinPacketRawGetParentOf(packet);

    WinPacketRawDecrementChildCountOf(parent);
    WinPacketRawFreeClone(packet);
}

static void
WinPacketFreeClonedRecurvise(PWIN_PACKET Packet)
{
    PWIN_PACKET_RAW packet = WinPacketToRawPacket(Packet);
    PWIN_PACKET_RAW parent = WinPacketRawGetParentOf(packet);

    WinPacketRawFreeClone(packet);

    if (WinPacketRawDecrementChildCountOf(parent) == 0) {
        WinPacketFreeRecursive(WinPacketFromRawPacket(parent));
    }
}

void
WinPacketFreeRecursive(PWIN_PACKET Packet)
{
    PWIN_PACKET_RAW packet = WinPacketToRawPacket(Packet);
    WinAssert(WinPacketRawGetChildCountOf(packet) == 0);

    if (WinPacketRawIsOwned(packet)) {
        if (WinPacketIsCloned(Packet)) {
            WinPacketFreeClonedRecurvise(Packet);
        } else {
            WinPacketRawFreeCreated(packet);
        }
    } else {
        WinPacketRawComplete(packet);
    }
}

PWIN_PACKET_LIST
WinPacketSplitMultiPacket(PWIN_MULTI_PACKET WinMultiPacket)
{
    PWIN_PACKET_RAW packet = WinMultiPacketToRawPacket(WinMultiPacket);
    PWIN_SUB_PACKET firstSub = WinPacketRawGetFirstSubPacket(packet);
    if (firstSub == NULL) {
        return NULL;
    }

    if (WinSubPacketRawGetNext(firstSub) == NULL) {
        PWIN_PACKET_LIST element = WinPacketListRawAllocateElement();
        if (element == NULL) {
            return NULL;
        }

        element->WinPacket = WinPacketFromRawPacket(packet);
        return element;
    }

    PWIN_PACKET_LIST clonedWinPacketList = NULL;
    PWIN_PACKET_LIST *pNextElement = &clonedWinPacketList;
    PWIN_SUB_PACKET nextSub = NULL;

    for (PWIN_SUB_PACKET sub = firstSub; sub != NULL; sub = nextSub) {
        WinPacketRawSetFirstSubPacket(packet, sub);
        nextSub = WinSubPacketRawGetNext(sub);
        WinSubPacketRawSetNext(sub, NULL);

        PWIN_PACKET clonedPacket = WinPacketClone(WinPacketFromRawPacket(packet));

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

    WinPacketRawSetFirstSubPacket(packet, firstSub);

    return clonedWinPacketList;

cleanup:
    WinPacketRawSetFirstSubPacket(packet, firstSub);

    PWIN_PACKET_LIST nextListElement = NULL;
    for (PWIN_PACKET_LIST clonedListElement = clonedWinPacketList; clonedListElement != NULL; clonedListElement = nextListElement) {
        nextListElement = clonedListElement->Next;
        WinPacketFreeClonedPreservingParent(clonedListElement->WinPacket);
        WinPacketListRawFreeElement(clonedListElement);
    }

    return NULL;
}
