/*
 * win_packet_raw.c -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_packet.h"
#include "windows_nbl.h"

#include <ndis.h>

struct _WIN_PACKET {
    NET_BUFFER_LIST NetBufferList;
};

VOID
WinPacketRawSetParentOf(PWIN_PACKET Packet, PWIN_PACKET Parent)
{
    PNET_BUFFER_LIST parentNbl = WinPacketToNBL(Parent);
    PNET_BUFFER_LIST childNbl = WinPacketToNBL(Packet);

    childNbl->ParentNetBufferList = parentNbl;
}

VOID
WinPacketRawIncrementChildCountOf(PWIN_PACKET Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketToNBL(Packet);
    InterlockedIncrement(&nbl->ChildRefCount);
}

static PWIN_PACKET
WinPacketRawAllocateClone_Impl(PWIN_PACKET Packet)
{
    NDIS_STATUS status;

    PNET_BUFFER_LIST originalNbl = WinPacketToNBL(Packet);
    PNET_BUFFER_LIST clonedNbl = NdisAllocateCloneNetBufferList(originalNbl, VrNBLPool, NULL, 0);
    if (clonedNbl == NULL) {
        goto failure;
    }

    clonedNbl->SourceHandle = VrSwitchObject->NdisFilterHandle;

    status = CreateForwardingContext(clonedNbl);
    if (status != NDIS_STATUS_SUCCESS) {
        goto cleanup_cloned_nbl;
    }

    status = VrSwitchObject->NdisSwitchHandlers.CopyNetBufferListInfo(
        VrSwitchObject->NdisSwitchContext, clonedNbl, originalNbl, 0);
    if (status != NDIS_STATUS_SUCCESS) {
        goto cleanup_forwarding_context;
    }

    return WinPacketFromNBL(clonedNbl);

cleanup_forwarding_context:
    FreeForwardingContext(clonedNbl);

cleanup_cloned_nbl:
    NdisFreeCloneNetBufferList(clonedNbl, 0);

failure:
    return NULL;
}
PWIN_PACKET (*WinPacketRawAllocateClone)(PWIN_PACKET Packet) = WinPacketRawAllocateClone_Impl;

PNET_BUFFER_LIST
WinPacketToNBL(PWIN_PACKET Packet)
{
    return &Packet->NetBufferList;
}

PWIN_PACKET
WinPacketFromNBL(PNET_BUFFER_LIST NetBufferList)
{
    return (PWIN_PACKET)NetBufferList;
}
