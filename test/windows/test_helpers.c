/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include "test_helpers.h"

#include "windows_nbl.h"

#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

PNET_BUFFER_LIST AllocateMockNetBufferList(NDIS_HANDLE NBLPool, ULONG nNetBuffers) {
    PNET_BUFFER_LIST nbl = NdisAllocateNetBufferAndNetBufferList(NBLPool, 0, 0, NULL, 0, 0);
    assert_non_null(nbl);
    NDIS_STATUS status = VrSwitchObject->NdisSwitchHandlers.AllocateNetBufferListForwardingContext(
        VrSwitchObject->NdisSwitchContext,
        nbl);
    assert(status == STATUS_SUCCESS);

    PNET_BUFFER *pNextNb = &NET_BUFFER_LIST_FIRST_NB(nbl);
    for (ULONG i = 1; i <= nNetBuffers; ++i) {
        PNET_BUFFER nb = test_calloc(1, sizeof(NET_BUFFER));
        assert_non_null(nb);
        nb->TestContentTag = i;
        *pNextNb = nb;
        pNextNb = &NET_BUFFER_NEXT_NB(nb);
    }

    return nbl;
}

struct vr_packet *AllocateMockNetBufferListWithVrPacket() {
    PNET_BUFFER_LIST nbl = AllocateMockNetBufferList(VrNBLPool, 0);

    struct vr_packet *pkt = test_calloc(1, sizeof(struct vr_packet));
    assert_non_null(pkt);

    pkt->vp_net_buffer_list = nbl;
    return pkt;
}

NDIS_STATUS MockAllocateNetBufferListForwardingContext(
  NDIS_SWITCH_CONTEXT NdisSwitchContext,
  PNET_BUFFER_LIST NetBufferList
) {
    NetBufferList->Context = test_calloc(1, sizeof(NET_BUFFER_LIST_CONTEXT));
    return STATUS_SUCCESS;
}

void MockFreeNetBufferListForwardingContext(
  NDIS_SWITCH_CONTEXT NdisSwitchContext,
  PNET_BUFFER_LIST NetBufferList
) {
    test_free(NetBufferList->Context);
    NetBufferList->Context = NULL;
}

NDIS_STATUS MockCopyNetBufferListInfo(
  NDIS_SWITCH_CONTEXT NdisSwitchContext,
  PNET_BUFFER_LIST DestNetBufferList,
  PNET_BUFFER_LIST SrcNetBufferList,
  UINT32 Flags
) {
    assert_non_null(SrcNetBufferList);
    assert_non_null(SrcNetBufferList->Context);
    assert_non_null(DestNetBufferList);
    assert_non_null(DestNetBufferList->Context);
    *DestNetBufferList->Context = *SrcNetBufferList->Context;
    return STATUS_SUCCESS;
}

void InitializeVrSwitchObject(void) {
    VrSwitchObject = calloc(1, sizeof(SWITCH_OBJECT));
    VrSwitchObject->NdisSwitchHandlers.AllocateNetBufferListForwardingContext = MockAllocateNetBufferListForwardingContext;
    VrSwitchObject->NdisSwitchHandlers.FreeNetBufferListForwardingContext = MockFreeNetBufferListForwardingContext;
    VrSwitchObject->NdisSwitchHandlers.CopyNetBufferListInfo = MockCopyNetBufferListInfo;
}

void FreeNblChain(PNET_BUFFER_LIST nblList) {
    PNET_BUFFER_LIST nextNbl;
    for (; nblList; nblList = nextNbl) {
        nextNbl = NET_BUFFER_LIST_NEXT_NBL(nblList);
        NET_BUFFER_LIST_NEXT_NBL(nblList) = NULL;
        FreeNetBufferList(nblList);
    }
}
