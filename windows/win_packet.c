/*
 * win_packet.c -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_packet.h"

#include "win_assert.h"

PWIN_PACKET
WinPacketClone(PWIN_PACKET Packet)
{
    PWIN_PACKET cloned = WinPacketRawAllocateClone(Packet);
    if (cloned == NULL) {
        return NULL;
    }

    WinPacketRawSetParentOf(cloned, Packet);
    WinPacketRawIncrementChildCountOf(Packet);

    return cloned;
}

static bool
WinPacketIsCloned(PWIN_PACKET Packet)
{
    return WinPacketRawGetParentOf(Packet) != NULL;
}

void
WinPacketFreeClonedPreservingParent(PWIN_PACKET Packet)
{
    PWIN_PACKET parent = WinPacketRawGetParentOf(Packet);

    WinPacketRawDecrementChildCountOf(parent);
    WinPacketRawFreeClone(Packet);
}

static void
WinPacketFreeClonedRecurvise(PWIN_PACKET Packet)
{
    PWIN_PACKET parent = WinPacketRawGetParentOf(Packet);

    WinPacketRawFreeClone(Packet);

    if (WinPacketRawDecrementChildCountOf(parent) == 0) {
        WinPacketFreeRecursive(parent);
    }
}

void
WinPacketFreeRecursive(PWIN_PACKET Packet)
{
    WinAssert(WinPacketRawGetChildCountOf(Packet) == 0);

    if (WinPacketRawIsOwned(Packet)) {
        if (WinPacketIsCloned(Packet)) {
            WinPacketFreeClonedRecurvise(Packet);
        } else {
            WinPacketRawFreeCreated(Packet);
        }
    } else {
        WinPacketRawComplete(Packet);
    }
}

PWIN_PACKET_LIST
WinPacketSplitMultiPacket(PWIN_MULTI_PACKET WinMultiPacket)
{
    PWIN_SUB_PACKET firstSub = WinMultiPacketRawGetFirstSubPacket(WinMultiPacket);
    if (firstSub == NULL) {
        return NULL;
    }

    if (WinSubPacketRawGetNext(firstSub) == NULL) {
        PWIN_PACKET_LIST element = WinPacketListRawAllocateElement();
        if (element == NULL) {
            return NULL;
        }

        element->WinPacket = WinMultiPacketRawToWinPacket(WinMultiPacket);
        return element;
    }

    PWIN_PACKET_LIST clonedWinPacketList = NULL;
    PWIN_PACKET_LIST *pNextElement = &clonedWinPacketList;
    PWIN_SUB_PACKET nextSub = NULL;

    for (PWIN_SUB_PACKET sub = firstSub; sub != NULL; sub = nextSub) {
        WinMultiPacketRawSetFirstSubPacket(WinMultiPacket, sub);
        nextSub = WinSubPacketRawGetNext(sub);
        WinSubPacketRawSetNext(sub, NULL);

        PWIN_PACKET clonedPacket = WinPacketClone(WinMultiPacketRawToWinPacket(WinMultiPacket));

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

    WinMultiPacketRawSetFirstSubPacket(WinMultiPacket, firstSub);

    return clonedWinPacketList;

cleanup:
    WinMultiPacketRawSetFirstSubPacket(WinMultiPacket, firstSub);

    PWIN_PACKET_LIST nextListElement = NULL;
    for (PWIN_PACKET_LIST clonedListElement = clonedWinPacketList; clonedListElement != NULL; clonedListElement = nextListElement) {
        nextListElement = clonedListElement->Next;
        WinPacketFreeClonedPreservingParent(clonedListElement->WinPacket);
        WinPacketListRawFreeElement(clonedListElement);
    }

    return NULL;
}
