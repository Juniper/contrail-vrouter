/*
 * win_packet_raw.c -- wrapper interface for Windows packet subsystem
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include "win_packet_raw.h"
#include "windows_nbl.h"

#include <ndis.h>

struct _WIN_PACKET {
    NET_BUFFER_LIST NetBufferList;
};

struct _WIN_SUB_PACKET {
    NET_BUFFER NetBuffer;
}

struct _WIN_MULTI_PACKET {
    NET_BUFFER_LIST NetBufferList;
}

PWIN_PACKET
WinPacketRawGetParentOf(PWIN_PACKET Packet)
{
    PNET_BUFFER_LIST childNbl = WinPacketToNBL(Packet);
    PNET_BUFFER_LIST parentNbl = childNbl->ParentNetBufferList;

    return WinPacketFromNBL(parentNbl);
}

void
WinPacketRawSetParentOf(PWIN_PACKET Packet, PWIN_PACKET Parent)
{
    PNET_BUFFER_LIST parentNbl = WinPacketToNBL(Parent);
    PNET_BUFFER_LIST childNbl = WinPacketToNBL(Packet);

    childNbl->ParentNetBufferList = parentNbl;
}

long
WinPacketRawGetChildCountOf(PWIN_PACKET Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketToNBL(Packet);
    return nbl->ChildRefCount;
}

long
WinPacketRawIncrementChildCountOf(PWIN_PACKET Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketToNBL(Packet);
    return InterlockedIncrement(&nbl->ChildRefCount);
}

long
WinPacketRawDecrementChildCountOf(PWIN_PACKET Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketToNBL(Packet);
    return InterlockedDecrement(&nbl->ChildRefCount);
}

bool
WinPacketRawIsOwned(PWIN_PACKET Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketToNBL(Packet);
    return nbl->NdisPoolHandle == VrNBLPool;
}

void
WinPacketRawComplete(PWIN_PACKET Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketToNBL(Packet);

    ASSERT(nbl != NULL);

    /* Flag SINGLE_SOURCE is used, because of singular NBLS */
    NdisFSendNetBufferListsComplete(VrSwitchObject->NdisFilterHandle,
        nbl, NDIS_SEND_COMPLETE_FLAGS_SWITCH_SINGLE_SOURCE);
}

void
WinPacketRawFreeCreated(PWIN_PACKET Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketToNBL(Packet);

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

PWIN_PACKET
WinPacketRawAllocateClone(PWIN_PACKET Packet)
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

void
WinPacketRawFreeClone(PWIN_PACKET Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketToNBL(Packet);

    FreeForwardingContext(nbl);
    NdisFreeCloneNetBufferList(nbl, 0);
}

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
