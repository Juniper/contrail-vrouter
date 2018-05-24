/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include "ndis.h"

#include <setjmp.h>
#include <cmocka.h>

VOID NdisAdvanceNetBufferListDataStart(
    PNET_BUFFER_LIST            NetBufferList,
    ULONG                       DataOffsetDelta,
    BOOLEAN                     FreeMdl,
    NET_BUFFER_FREE_MDL_HANDLER FreeMdlHandler
) {
    assert(0);
}

PVOID NdisGetDataBuffer(
    PNET_BUFFER NetBuffer,
    ULONG       BytesNeeded,
    PVOID       Storage,
    UINT        AlignMultiple,
    UINT        AlignOffset
) {
    assert(0);
    return NULL;
}

VOID NdisFSendNetBufferLists(
    NDIS_HANDLE      NdisFilterHandle,
    PNET_BUFFER_LIST NetBufferLists,
    NDIS_PORT_NUMBER PortNumber,
    ULONG            SendFlags
) {
    assert(0);
}

PMDL NdisAllocateMdl(
  NDIS_HANDLE NdisHandle,
  PVOID       VirtualAddress,
  UINT        Length
) {
    assert(0);
    return NULL;
}

PNET_BUFFER_LIST NdisAllocateNetBufferAndNetBufferList(
  NDIS_HANDLE           PoolHandle,
  USHORT                ContextSize,
  USHORT                ContextBackFill,
  PMDL                  MdlChain,
  ULONG                 DataOffset,
  SIZE_T                DataLength
) {
    PNET_BUFFER_LIST nbl = test_calloc(1, sizeof(NET_BUFFER_LIST));
    nbl->NdisPoolHandle = PoolHandle;
    return nbl;
}

PNET_BUFFER_LIST NdisAllocateCloneNetBufferList(
  PNET_BUFFER_LIST OriginalNetBufferList,
  NDIS_HANDLE      NetBufferListPoolHandle,
  NDIS_HANDLE      NetBufferPoolHandle,
  ULONG            AllocateCloneFlags
) {
    PNET_BUFFER_LIST nbl = test_calloc(1, sizeof(NET_BUFFER_LIST));
    nbl->NdisPoolHandle = NetBufferListPoolHandle;
    return nbl;
}

PNET_BUFFER_LIST NdisAllocateReassembledNetBufferList(
  PNET_BUFFER_LIST FragmentNetBufferList,
  NDIS_HANDLE      NetBufferAndNetBufferListPoolHandle,
  ULONG            StartOffset,
  ULONG            DataOffsetDelta,
  ULONG            DataBackFill,
  ULONG            AllocateReassembleFlags
) {
    assert(0);
    return NULL;
}

PNET_BUFFER_LIST NdisAllocateFragmentNetBufferList(
  PNET_BUFFER_LIST OriginalNetBufferList,
  NDIS_HANDLE      NetBufferListPool,
  NDIS_HANDLE      NetBufferPool,
  ULONG            StartOffset,
  ULONG            MaximumLength,
  ULONG            DataOffsetDelta,
  ULONG            DataBackFill,
  ULONG            AllocateFragmentFlags
) {
    assert(0);
    return NULL;
}

void NdisFreeNetBufferList(
  __drv_freesMem(mem)PNET_BUFFER_LIST NetBufferList
) {
    test_free(NetBufferList);
}

void NdisFreeCloneNetBufferList(
  __drv_freesMem(mem)PNET_BUFFER_LIST CloneNetBufferList,
  ULONG                               FreeCloneFlags
) {
    test_free(CloneNetBufferList);
}

void NdisFreeMdl(
  __drv_freesMem(mem)PMDL Mdl
) {
    assert(0);
}

void NdisFSendNetBufferListsComplete(
  NDIS_HANDLE      NdisFilterHandle,
  PNET_BUFFER_LIST NetBufferList,
  ULONG            SendCompleteFlags
) {
    NetBufferList->TestIsCompleted = 1;
}

void NdisAcquireRWLockRead(
  PNDIS_RW_LOCK_EX            Lock,
  _IRQL_saves_ PLOCK_STATE_EX LockState,
  UCHAR                       Flags
) {}

void NdisReleaseRWLock(
  PNDIS_RW_LOCK_EX               Lock,
  _IRQL_restores_ PLOCK_STATE_EX LockState
) {}
