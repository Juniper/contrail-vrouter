/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include "precomp.h"
#include "vr_windows.h"

FILTER_OID_REQUEST FilterOidRequest;
FILTER_OID_REQUEST_COMPLETE FilterOidRequestComplete;
FILTER_CANCEL_OID_REQUEST FilterCancelOidRequest;

static VOID
VrStoreOriginalOidRequest(PNDIS_OID_REQUEST OidRequest, PNDIS_OID_REQUEST OriginalOidRequest)
{
    *(PVOID*)(&OidRequest->SourceReserved[0 * sizeof(PVOID)]) = OriginalOidRequest;
}

static PNDIS_OID_REQUEST
VrRetrieveOriginalOidRequest(PNDIS_OID_REQUEST OidRequest)
{
    return *(PVOID*)(&OidRequest->SourceReserved[0 * sizeof(PVOID)]);
}

static VOID
VrStoreOidRequestStatusHandle(PNDIS_OID_REQUEST OidRequest, PVR_OID_REQUEST_STATUS OidRequestStatus)
{
    *(PVOID*)(&OidRequest->SourceReserved[1 * sizeof(PVOID)]) = OidRequestStatus;
}

static PVR_OID_REQUEST_STATUS
VrRetrieveOidRequestStatusHandle(PNDIS_OID_REQUEST OidRequest)
{
    return *(PVOID*)(&OidRequest->SourceReserved[1 * sizeof(PVOID)]);
}

static VOID
VrCompleteInternalOidRequest(PNDIS_OID_REQUEST NdisRequest, NDIS_STATUS Status)
{
    PVR_OID_REQUEST_STATUS oidRequestStatus;

    ASSERTMSG("Unsupported NDIS OID RequestType", NdisRequest->RequestType == NdisRequestQueryInformation);

    oidRequestStatus = VrRetrieveOidRequestStatusHandle(NdisRequest);
    oidRequestStatus->Status = Status;
    oidRequestStatus->BytesNeeded = NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded;

    NdisSetEvent(&oidRequestStatus->ReqEvent);
}

static NDIS_STATUS
VrQuerySwitchNicArray(PSWITCH_OBJECT Switch, PVOID Buffer, ULONG BufferLength, PULONG OutputBytesNeeded)
{
    PNDIS_OID_REQUEST oidRequest;
    PVR_OID_REQUEST_STATUS oidRequestStatus;
    NDIS_STATUS status;

    oidRequestStatus = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*oidRequestStatus), VrAllocationTag);
    if (oidRequestStatus == NULL) {
        return NDIS_STATUS_RESOURCES;
    }

    oidRequest = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*oidRequest), VrAllocationTag);
    if (oidRequest == NULL) {
        ExFreePool(oidRequestStatus);
        return NDIS_STATUS_RESOURCES;
    }

    RtlZeroMemory(oidRequestStatus, sizeof(*oidRequestStatus));
    NdisInitializeEvent(&oidRequestStatus->ReqEvent);

    RtlZeroMemory(oidRequest, sizeof(*oidRequest));
    VrStoreOidRequestStatusHandle(oidRequest, oidRequestStatus);

    oidRequest->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
    oidRequest->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
    oidRequest->Header.Size = sizeof(NDIS_OID_REQUEST);
    oidRequest->RequestType = NdisRequestQueryInformation;
    oidRequest->Timeout = 0;
    oidRequest->RequestId = (PVOID)VrOidRequestId;

    oidRequest->DATA.QUERY_INFORMATION.Oid = OID_SWITCH_NIC_ARRAY;
    oidRequest->DATA.QUERY_INFORMATION.InformationBuffer = Buffer;
    oidRequest->DATA.QUERY_INFORMATION.InformationBufferLength = BufferLength;

    NdisInterlockedIncrement(&Switch->PendingOidCount);
    status = NdisFOidRequest(Switch->NdisFilterHandle, oidRequest);
    if (status == NDIS_STATUS_PENDING) {
        NdisWaitEvent(&oidRequestStatus->ReqEvent, 0);
    } else {
        VrCompleteInternalOidRequest(oidRequest, status);
        NdisInterlockedDecrement(&Switch->PendingOidCount);
    }

    if (OutputBytesNeeded != NULL) {
        *OutputBytesNeeded = oidRequestStatus->BytesNeeded;
    }

    VrStoreOidRequestStatusHandle(oidRequest, NULL);
    ExFreePool(oidRequest);
    status = oidRequestStatus->Status;
    ExFreePool(oidRequestStatus);

    return status;
}

NDIS_STATUS
VrGetNicArray(PSWITCH_OBJECT Switch, PNDIS_SWITCH_NIC_ARRAY *OutputNicArray)
{
    NDIS_STATUS status;
    PNDIS_SWITCH_NIC_ARRAY nicArray = NULL;
    ULONG nicArrayLength = 0;

    if (OutputNicArray == NULL) {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    status = VrQuerySwitchNicArray(Switch, 0, 0, &nicArrayLength);
    if (status != NDIS_STATUS_INVALID_LENGTH) {
        DbgPrint("vRouter:%s(): OID_SWITCH_NIC_ARRAY did not return required buffer size\n", __func__);
        return NDIS_STATUS_FAILURE;
    }

    nicArray = ExAllocatePoolWithTag(NonPagedPoolNx, nicArrayLength, VrAllocationTag);
    if (nicArray == NULL) {
        return NDIS_STATUS_RESOURCES;
    }

    nicArray->Header.Revision = NDIS_SWITCH_PORT_ARRAY_REVISION_1;
    nicArray->Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nicArray->Header.Size = (USHORT)nicArrayLength;

    status = VrQuerySwitchNicArray(Switch, nicArray, nicArrayLength, NULL);
    if (status == NDIS_STATUS_SUCCESS) {
        *OutputNicArray = nicArray;
    } else {
        ExFreePool(nicArray);
    }

    return status;
}

VOID
VrFreeNicArray(PNDIS_SWITCH_NIC_ARRAY NicArray)
{
    if (NicArray != NULL) {
        ExFreePool(NicArray);
    }
}

static VOID
CopyCompletedOidRequestData(PNDIS_OID_REQUEST OriginalOidRequest, PNDIS_OID_REQUEST CompletedOidRequest)
{
    switch (CompletedOidRequest->RequestType)
    {
        case NdisRequestQueryInformation:
        case NdisRequestQueryStatistics:
            OriginalOidRequest->DATA.QUERY_INFORMATION.BytesWritten =
                CompletedOidRequest->DATA.QUERY_INFORMATION.BytesWritten;
            OriginalOidRequest->DATA.QUERY_INFORMATION.BytesNeeded =
                CompletedOidRequest->DATA.QUERY_INFORMATION.BytesNeeded;

            break;

        case NdisRequestSetInformation:
            OriginalOidRequest->DATA.SET_INFORMATION.BytesRead =
                CompletedOidRequest->DATA.SET_INFORMATION.BytesRead;
            OriginalOidRequest->DATA.SET_INFORMATION.BytesNeeded =
                CompletedOidRequest->DATA.SET_INFORMATION.BytesNeeded;

            break;

        case NdisRequestMethod:
            OriginalOidRequest->DATA.METHOD_INFORMATION.OutputBufferLength =
                CompletedOidRequest->DATA.METHOD_INFORMATION.OutputBufferLength;
            OriginalOidRequest->DATA.METHOD_INFORMATION.BytesRead =
                CompletedOidRequest->DATA.METHOD_INFORMATION.BytesRead;
            OriginalOidRequest->DATA.METHOD_INFORMATION.BytesNeeded =
                CompletedOidRequest->DATA.METHOD_INFORMATION.BytesNeeded;
            OriginalOidRequest->DATA.METHOD_INFORMATION.BytesWritten =
                CompletedOidRequest->DATA.METHOD_INFORMATION.BytesWritten;

            break;
    }
}

NDIS_STATUS
FilterOidRequest(NDIS_HANDLE FilterModuleContext, PNDIS_OID_REQUEST OidRequest)
{
    PSWITCH_OBJECT switchObject = (PSWITCH_OBJECT)FilterModuleContext;
    NDIS_STATUS status = NDIS_STATUS_SUCCESS;
    PNDIS_OID_REQUEST clonedRequest = NULL;

    DbgPrint("%s: OidRequest %p.\r\n", __func__, OidRequest);

    status = NdisAllocateCloneOidRequest(switchObject->NdisFilterHandle,
                                         OidRequest,
                                         VrAllocationTag,
                                         &clonedRequest);
    if (status != NDIS_STATUS_SUCCESS)
    {
        DbgPrint("%s: Cannot Clone OidRequest\r\n", __func__);
        return status;
    }

    VrStoreOriginalOidRequest(clonedRequest, OidRequest);
    NdisInterlockedIncrement(&switchObject->PendingOidCount);

    KeMemoryBarrier();

    status = NdisFOidRequest(switchObject->NdisFilterHandle, clonedRequest);
    if (status != NDIS_STATUS_PENDING)
    {
        FilterOidRequestComplete(switchObject, clonedRequest, status);
        return NDIS_STATUS_PENDING;
    }

    return status;
}

void
FilterOidRequestComplete(
    NDIS_HANDLE FilterModuleContext,
    PNDIS_OID_REQUEST NdisOidRequest,
    NDIS_STATUS Status)
{
    PSWITCH_OBJECT switchObject = (PSWITCH_OBJECT)FilterModuleContext;
    PNDIS_OID_REQUEST originalRequest;

    DbgPrint("%s: NdisOidRequest %p.\r\n", __func__, NdisOidRequest);

    originalRequest = VrRetrieveOriginalOidRequest(NdisOidRequest);
    if (originalRequest == NULL)
    {
        VrCompleteInternalOidRequest(NdisOidRequest, Status);
    }
    else
    {
        CopyCompletedOidRequestData(originalRequest, NdisOidRequest);
        VrStoreOriginalOidRequest(NdisOidRequest, NULL);

        NdisFreeCloneOidRequest(switchObject->NdisFilterHandle, NdisOidRequest);
        NdisFOidRequestComplete(switchObject->NdisFilterHandle, originalRequest, Status);
    }

    NdisInterlockedDecrement(&switchObject->PendingOidCount);
}

void
FilterCancelOidRequest(NDIS_HANDLE FilterModuleContext, PVOID RequestId)
{
    PSWITCH_OBJECT switchObject = (PSWITCH_OBJECT)FilterModuleContext;

    NdisFCancelOidRequest(switchObject->NdisFilterHandle, RequestId);
}
