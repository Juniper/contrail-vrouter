/*
 * win_packet_raw.c -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_packet_raw.h"
#include "win_packet.h"
#include "windows_nbl.h"

#include <ndis.h>

struct _WIN_PACKET_RAW {
    NET_BUFFER_LIST NetBufferList;
};

static const ULONG PacketListAllocationTag = 'ELPW';

PWIN_PACKET_RAW
WinPacketRawGetParentOf(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST childNbl = WinPacketRawToNBL(Packet);
    PNET_BUFFER_LIST parentNbl = childNbl->ParentNetBufferList;

    return WinPacketRawFromNBL(parentNbl);
}

void
WinPacketRawSetParentOf(PWIN_PACKET_RAW Packet, PWIN_PACKET_RAW Parent)
{
    PNET_BUFFER_LIST parentNbl = WinPacketRawToNBL(Parent);
    PNET_BUFFER_LIST childNbl = WinPacketRawToNBL(Packet);

    childNbl->ParentNetBufferList = parentNbl;
}

long
WinPacketRawGetChildCountOf(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    return nbl->ChildRefCount;
}

long
WinPacketRawIncrementChildCountOf(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    return InterlockedIncrement(&nbl->ChildRefCount);
}

long
WinPacketRawDecrementChildCountOf(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    return InterlockedDecrement(&nbl->ChildRefCount);
}

bool
WinPacketRawIsOwned(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);
    return nbl->NdisPoolHandle == VrNBLPool;
}

void
WinPacketRawComplete(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    ASSERT(nbl != NULL);

    /* Flag SINGLE_SOURCE is used, because of singular NBLS */
    NdisFSendNetBufferListsComplete(VrSwitchObject->NdisFilterHandle,
        nbl, NDIS_SEND_COMPLETE_FLAGS_SWITCH_SINGLE_SOURCE);
}

void
WinPacketRawFreeCreated(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    ASSERT(nbl != NULL);
    ASSERTMSG("A non-singular NBL made it's way into the process", nbl->Next == NULL);

    PNET_BUFFER nb = NULL;
    PMDL mdl = NULL;
    PMDL mdl_next = NULL;
    PVOID data = NULL;

    FreeForwardingContext(nbl);

    /* Free MDLs associated with NET_BUFFERS */
    for (nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb != NULL; nb = NET_BUFFER_NEXT_NB(nb))
        for (mdl = NET_BUFFER_FIRST_MDL(nb); mdl != NULL; mdl = mdl_next) {
            mdl_next = mdl->Next;
            data = MmGetSystemAddressForMdlSafe(mdl, LowPagePriority | MdlMappingNoExecute);
            NdisFreeMdl(mdl);
            if (data != NULL)
                ExFreePool(data);
        }

    NdisFreeNetBufferList(nbl);
}

PWIN_PACKET_RAW
WinPacketRawAllocateClone(PWIN_PACKET_RAW Packet)
{
    NDIS_STATUS status;

    PNET_BUFFER_LIST originalNbl = WinPacketRawToNBL(Packet);
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

    return WinPacketRawFromNBL(clonedNbl);

cleanup_forwarding_context:
    FreeForwardingContext(clonedNbl);

cleanup_cloned_nbl:
    NdisFreeCloneNetBufferList(clonedNbl, 0);

failure:
    return NULL;
}

void
WinPacketRawFreeClone(PWIN_PACKET_RAW Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketRawToNBL(Packet);

    FreeForwardingContext(nbl);
    NdisFreeCloneNetBufferList(nbl, 0);
}

PNET_BUFFER_LIST
WinPacketRawToNBL(PWIN_PACKET_RAW Packet)
{
    return &Packet->NetBufferList;
}

PWIN_PACKET_RAW
WinPacketRawFromNBL(PNET_BUFFER_LIST NetBufferList)
{
    return (PWIN_PACKET_RAW)NetBufferList;
}
