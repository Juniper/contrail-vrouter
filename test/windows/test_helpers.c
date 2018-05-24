/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include "test_helpers.h"

PNET_BUFFER_LIST AllocateMockNetBufferList(NDIS_HANDLE NBLPool) {
    PNET_BUFFER_LIST nbl = NdisAllocateNetBufferAndNetBufferList(NBLPool, 0, 0, NULL, 0, 0);
    assert_non_null(nbl);
    NDIS_STATUS status = VrSwitchObject->NdisSwitchHandlers.AllocateNetBufferListForwardingContext(
        VrSwitchObject->NdisSwitchContext,
        nbl);
    assert(status == STATUS_SUCCESS);
    return nbl;
}

struct vr_packet *AllocateMockNetBufferListWithVrPacket() {
    PNET_BUFFER_LIST nbl = AllocateMockNetBufferList(VrNBLPool);

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
