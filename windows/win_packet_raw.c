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

PWIN_PACKET
WinPacketRawGetParentOf(PWIN_PACKET Packet)
{
    PNET_BUFFER_LIST childNbl = WinPacketToNBL(Packet);
    PNET_BUFFER_LIST parentNbl = childNbl->ParentNetBufferList;

    return WinPacketFromNBL(parentNbl);
}

VOID
WinPacketRawSetParentOf(PWIN_PACKET Packet, PWIN_PACKET Parent)
{
    PNET_BUFFER_LIST parentNbl = WinPacketToNBL(Parent);
    PNET_BUFFER_LIST childNbl = WinPacketToNBL(Packet);

    childNbl->ParentNetBufferList = parentNbl;
}

LONG
WinPacketRawGetChildCountOf(PWIN_PACKET Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketToNBL(Packet);
    return nbl->ChildRefCount;
}

LONG
WinPacketRawIncrementChildCountOf(PWIN_PACKET Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketToNBL(Packet);
    return InterlockedIncrement(&nbl->ChildRefCount);
}

LONG
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

static VOID
WinPacketRawComplete_Impl(PWIN_PACKET Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketToNBL(Packet);

    ASSERT(nbl != NULL);

    /* Flag SINGLE_SOURCE is used, because of singular NBLS */
    NdisFSendNetBufferListsComplete(VrSwitchObject->NdisFilterHandle,
        nbl, NDIS_SEND_COMPLETE_FLAGS_SWITCH_SINGLE_SOURCE);
}
VOID (*WinPacketRawComplete)(PWIN_PACKET Packet) = WinPacketRawComplete_Impl;

static VOID
WinPacketRawFreeCreated_Impl(PWIN_PACKET Packet)
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
void (*WinPacketRawFreeCreated)(PWIN_PACKET Packet) = WinPacketRawFreeCreated_Impl;

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

VOID 
WinPacketRawFreeClone_Impl(PWIN_PACKET Packet)
{
    PNET_BUFFER_LIST nbl = WinPacketToNBL(Packet);

    FreeForwardingContext(nbl);
    NdisFreeCloneNetBufferList(nbl, 0);
}
VOID (*WinPacketRawFreeClone)(PWIN_PACKET Packet) = WinPacketRawFreeClone_Impl;

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

static PVOID 
WinRawAllocate_Impl(size_t size) 
{
    return ExAllocatePoolWithTag(NonPagedPoolNx, size, VrAllocationTag);
}

PVOID (*WinRawAllocate)(size_t size) = WinRawAllocate_Impl;

VOID 
WinRawFree(PVOID buffer)
{
    ExFreePool(buffer);
}