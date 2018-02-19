/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <ndis.h>

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
