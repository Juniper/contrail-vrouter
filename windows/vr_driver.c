/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_windows.h"
#include "windows_devices.h"
#include "windows_shmem.h"
#include "windows_nbl.h"
#include "win_interface.h"
#include "win_packetdump.h"

#include <vrouter.h>
#include <vr_packet.h>

static const PWSTR FriendlyName = L"OpenContrail's vRouter forwarding extension";
static const PWSTR UniqueName = L"{56553588-1538-4BE6-B8E0-CB46402DC205}";
static const PWSTR ServiceName = L"vRouter";

static PDRIVER_OBJECT VrDriverObject = NULL;
NDIS_HANDLE VrDriverHandle = NULL;

const ULONG VrAllocationTag = 'RVCO';
const ULONG VrOidRequestId = 'RVCO';

PSWITCH_OBJECT VrSwitchObject = NULL;
NDIS_HANDLE VrNBLPool = NULL;
NDIS_HANDLE VrNBPool = NULL;

/*
 * Read/write lock which must be acquired by deferred callbacks. Used in functions from
 * `host_os` struct.
 */
PNDIS_RW_LOCK_EX AsyncWorkRWLock = NULL;

unsigned int vr_num_cpus;
int vrouter_dbg = 0;

VR_BASIC_NIC_ENTRY ExternalNicEntry, VhostNicEntry;

/*
 * NDIS Function prototypes
 */
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

FILTER_ATTACH FilterAttach;
FILTER_DETACH FilterDetach;
FILTER_PAUSE FilterPause;
FILTER_RESTART FilterRestart;

static VOID UninitializeVRouter(pvr_switch_context ctx);

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NDIS_STATUS status;
    NDIS_FILTER_DRIVER_CHARACTERISTICS f_chars;
    NDIS_STRING service_name;
    NDIS_STRING friendly_name;
    NDIS_STRING unique_name;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&service_name, ServiceName);
    RtlInitUnicodeString(&friendly_name, FriendlyName);
    RtlInitUnicodeString(&unique_name, UniqueName);

    VrDriverObject = DriverObject;
    VrDriverObject->DriverUnload = DriverUnload;

    Pkt0Init();

    /*
     * Memory for the shmem tables is allocated here, because it must be valid
     * when IRP_MJ_CLOSE is sent on the shmem devices
     */
    status = ShmemInit();
    if (status != STATUS_SUCCESS) {
        return status;
    }

    NdisZeroMemory(&f_chars, sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS));
    f_chars.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
    f_chars.Header.Size = NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_2;
    f_chars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;

    f_chars.MajorNdisVersion = NDIS_FILTER_MAJOR_VERSION;
    f_chars.MinorNdisVersion = NDIS_FILTER_MINOR_VERSION;

    f_chars.MajorDriverVersion = 1;
    f_chars.MinorDriverVersion = 0;
    f_chars.Flags = 0;

    f_chars.FriendlyName = friendly_name;
    f_chars.UniqueName = unique_name;
    f_chars.ServiceName = service_name;

    f_chars.AttachHandler = FilterAttach;
    f_chars.DetachHandler = FilterDetach;
    f_chars.PauseHandler = FilterPause;
    f_chars.RestartHandler = FilterRestart;

    f_chars.SendNetBufferListsHandler = FilterSendNetBufferLists;
    f_chars.SendNetBufferListsCompleteHandler = FilterSendNetBufferListsComplete;

    f_chars.OidRequestHandler = FilterOidRequest;
    f_chars.OidRequestCompleteHandler = FilterOidRequestComplete;
    f_chars.CancelOidRequestHandler = FilterCancelOidRequest;

    f_chars.NetPnPEventHandler = FilterNetPnpEvent;

    status = NdisFRegisterFilterDriver(DriverObject,
                                       (NDIS_HANDLE)VrDriverObject,
                                       &f_chars,
                                       &VrDriverHandle);

    if (status != NDIS_STATUS_SUCCESS)
    {
        if (VrDriverHandle != NULL)
        {
            NdisFDeregisterFilterDriver(VrDriverHandle);
            VrDriverHandle = NULL;
        }
    }

    return status;
}

VOID
DriverUnload(PDRIVER_OBJECT DriverObject)
{
    if (VrSwitchObject) {
        VrSwitchObject->Running = FALSE;

        KeMemoryBarrier();
        while (VrSwitchObject->PendingOidCount > 0) {
            NdisMSleep(1000);
        }

        UninitializeVRouter(VrSwitchObject->ExtensionContext);
    }

    NdisFDeregisterFilterDriver(VrDriverHandle);

    ShmemExit();
}

static NDIS_HANDLE
VrGenerateNetBufferListPool(VOID)
{
    NET_BUFFER_LIST_POOL_PARAMETERS params;
    params.ContextSize = 0;
    params.DataSize = 0;
    params.fAllocateNetBuffer = TRUE;
    params.PoolTag = VrAllocationTag;
    params.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    params.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    params.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;

    NDIS_HANDLE pool = NdisAllocateNetBufferListPool(VrSwitchObject->NdisFilterHandle, &params);

    ASSERT(pool != NULL);

    return pool;
}

static void
VrFreeNetBufferListPool(NDIS_HANDLE pool)
{
    ASSERTMSG("NBL pool is not initialized", pool != NULL);
    NdisFreeNetBufferListPool(pool);
}

static NDIS_HANDLE
VrGenerateNetBufferPool(VOID)
{
    NET_BUFFER_POOL_PARAMETERS params;
    params.DataSize = 0;
    params.PoolTag = VrAllocationTag;
    params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    params.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    params.Header.Size = NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;

    NDIS_HANDLE pool = NdisAllocateNetBufferPool(VrSwitchObject->NdisFilterHandle, &params);

    ASSERT(pool != NULL);

    return pool;
}

static void
VrFreeNetBufferPool(NDIS_HANDLE pool)
{
    ASSERTMSG("NB pool is not initialized", pool != NULL);
    NdisFreeNetBufferPool(pool);
}

static VOID
UninitializeVRouter(pvr_switch_context ctx)
{
    if (ctx->assembler_up) {
        VrAssemblerExit();
        ctx->assembler_up = FALSE;
    }

    if (ctx->vrouter_up) {
        vrouter_exit(false);
        ctx->vrouter_up = FALSE;
    }

    if (ctx->message_up) {
        vr_message_exit();
        ctx->message_up = FALSE;
    }

    if (ctx->shmem_devices_up) {
        ShmemDestroyDevices();
        ctx->shmem_devices_up = FALSE;
    }

    if (ctx->pkt0_up) {
        Pkt0DestroyDevice();
        ctx->pkt0_up = FALSE;
    }

    if (ctx->ksync_up) {
        KsyncDestroyDevice();
        ctx->ksync_up = FALSE;
    }
}

static VOID
UninitializeWindowsComponents(pvr_switch_context ctx)
{
    if (VrNBLPool)
        VrFreeNetBufferListPool(VrNBLPool);

    if (VrNBPool)
        VrFreeNetBufferPool(VrNBPool);

    if (AsyncWorkRWLock)
        NdisFreeRWLock(AsyncWorkRWLock);

    if (ctx) {
        if (ctx->lock)
            NdisFreeRWLock(ctx->lock);

        ExFreePool(ctx);
    }
}

static NDIS_STATUS
InitializeVRouter(pvr_switch_context ctx)
{
    ASSERT(!ctx->ksync_up);
    ASSERT(!ctx->pkt0_up);
    ASSERT(!ctx->shmem_devices_up);
    ASSERT(!ctx->message_up);
    ASSERT(!ctx->vrouter_up);
    ASSERT(!ctx->assembler_up);

    /* Before any initialization happens, clean the shared memory tables */
    ShmemClean();

    BasicNicsClean();

    ctx->ksync_up = NT_SUCCESS(KsyncCreateDevice(VrDriverHandle));
    if (!ctx->ksync_up)
        goto cleanup;

    ctx->pkt0_up = NT_SUCCESS(Pkt0CreateDevice(VrDriverHandle));
    if (!ctx->pkt0_up)
        goto cleanup;

    ctx->shmem_devices_up = NT_SUCCESS(ShmemCreateDevices(VrDriverHandle));
    if (!ctx->shmem_devices_up)
        goto cleanup;

    ctx->message_up = !vr_message_init();
    if (!ctx->message_up)
        goto cleanup;

    ctx->vrouter_up = !vrouter_init();
    if (!ctx->vrouter_up)
        goto cleanup;

    ctx->assembler_up = !VrAssemblerInit();
    if (!ctx->assembler_up)
        goto cleanup;

    return NDIS_STATUS_SUCCESS;

cleanup:
    UninitializeVRouter(ctx);
    return NDIS_STATUS_FAILURE;
}

static NDIS_STATUS
InitializeWindowsComponents(PSWITCH_OBJECT Switch)
{
    InitPacketDumping();

    pvr_switch_context ctx = NULL;

    ctx = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(vr_switch_context), VrAllocationTag);
    if (ctx == NULL)
        return NDIS_STATUS_RESOURCES;

    RtlZeroMemory(ctx, sizeof(vr_switch_context));

    ctx->lock = NdisAllocateRWLock(Switch->NdisFilterHandle);
    if (ctx->lock == NULL)
        goto cleanup;

    AsyncWorkRWLock = NdisAllocateRWLock(Switch->NdisFilterHandle);
    if (AsyncWorkRWLock == NULL)
        goto cleanup;

    VrNBLPool = VrGenerateNetBufferListPool();
    if (VrNBLPool == NULL)
        goto cleanup;

    VrNBPool = VrGenerateNetBufferPool();
    if (VrNBPool == NULL)
        goto cleanup;

    Switch->ExtensionContext = ctx;

    return NDIS_STATUS_SUCCESS;

cleanup:
    UninitializeWindowsComponents(ctx);

    return NDIS_STATUS_FAILURE;
}

static PSWITCH_OBJECT
AllocateSwitchObject(NDIS_HANDLE NdisFilterHandle,
                     NDIS_SWITCH_CONTEXT SwitchContext,
                     NDIS_SWITCH_OPTIONAL_HANDLERS SwitchHandlers)
{
    ULONG switchObjectSize = sizeof(SWITCH_OBJECT);
    PSWITCH_OBJECT switchObject = ExAllocatePoolWithTag(NonPagedPoolNx, switchObjectSize, VrAllocationTag);
    if (switchObject == NULL) {
        return NULL;
    }

    RtlZeroMemory(switchObject, switchObjectSize);
    switchObject->Running = FALSE;

    // Initialize NDIS related information.
    switchObject->NdisFilterHandle = NdisFilterHandle;
    switchObject->NdisSwitchContext = SwitchContext;
    switchObject->NdisSwitchHandlers = SwitchHandlers;

    return switchObject;
}

static PSWITCH_OBJECT
CreateSwitch(NDIS_HANDLE NdisFilterHandle,
             NDIS_SWITCH_CONTEXT SwitchContext,
             NDIS_SWITCH_OPTIONAL_HANDLERS SwitchHandlers)
{
    if (VrSwitchObject != NULL)
        return NULL;

    vr_num_cpus = KeQueryActiveProcessorCount(NULL);
    if (vr_num_cpus == 0)
        return NULL;

    PSWITCH_OBJECT switchObj = AllocateSwitchObject(NdisFilterHandle, SwitchContext, SwitchHandlers);
    if (switchObj == NULL)
        return NULL;

    VrSwitchObject = switchObj;

    BOOLEAN windows = FALSE;
    BOOLEAN vrouter = FALSE;

    NDIS_STATUS status = InitializeWindowsComponents(switchObj);
    if (!NT_SUCCESS(status))
        goto cleanup;
    windows = TRUE;

    status = InitializeVRouter(switchObj->ExtensionContext);
    if (!NT_SUCCESS(status))
        goto cleanup;
    vrouter = TRUE;

    return switchObj;

cleanup:
    if (vrouter)
        UninitializeVRouter(switchObj->ExtensionContext);

    if (windows)
        UninitializeWindowsComponents(switchObj->ExtensionContext);

    ExFreePool(switchObj);
    VrSwitchObject = NULL;

    return NULL;
}

static NDIS_STATUS
SetFilterContextAndAttibutes(NDIS_HANDLE NdisFilterHandle, PSWITCH_OBJECT SwitchObject)
{
    NDIS_FILTER_ATTRIBUTES filterAttributes;

    filterAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
    filterAttributes.Header.Size = NDIS_SIZEOF_FILTER_ATTRIBUTES_REVISION_1;
    filterAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
    filterAttributes.Flags = 0;

    NDIS_DECLARE_FILTER_MODULE_CONTEXT(SWITCH_OBJECT);
    return NdisFSetAttributes(NdisFilterHandle, SwitchObject, &filterAttributes);
}

static NDIS_STATUS
GetSwitchHandlersAndContext(NDIS_HANDLE NdisFilterHandle,
                            PNDIS_SWITCH_CONTEXT OutContext,
                            PNDIS_SWITCH_OPTIONAL_HANDLERS OutHandlers)
{
    OutHandlers->Header.Type = NDIS_OBJECT_TYPE_SWITCH_OPTIONAL_HANDLERS;
    OutHandlers->Header.Size = NDIS_SIZEOF_SWITCH_OPTIONAL_HANDLERS_REVISION_1;
    OutHandlers->Header.Revision = NDIS_SWITCH_OPTIONAL_HANDLERS_REVISION_1;

    return NdisFGetOptionalSwitchHandlers(NdisFilterHandle, OutContext, OutHandlers);
}

NDIS_STATUS
FilterAttach(NDIS_HANDLE NdisFilterHandle,
             NDIS_HANDLE DriverContext,
             PNDIS_FILTER_ATTACH_PARAMETERS AttachParameters)
{
    UNREFERENCED_PARAMETER(DriverContext);
    NT_ASSERT(DriverContext == (NDIS_HANDLE)VrDriverObject);

    // Accept Ethernet only
    if (AttachParameters->MiniportMediaType != NdisMedium802_3) {
        return NDIS_STATUS_INVALID_PARAMETER;
    }

    NDIS_SWITCH_CONTEXT switchContext;
    NDIS_SWITCH_OPTIONAL_HANDLERS switchHandlers;
    NDIS_STATUS status = GetSwitchHandlersAndContext(NdisFilterHandle, &switchContext, &switchHandlers);
    if (status != NDIS_STATUS_SUCCESS) {
        return status;
    }

    PSWITCH_OBJECT switchObject = CreateSwitch(NdisFilterHandle, switchContext, switchHandlers);
    if (switchObject == NULL) {
        return NDIS_STATUS_FAILURE;
    }

    status = SetFilterContextAndAttibutes(NdisFilterHandle, switchObject);
    if (status != NDIS_STATUS_SUCCESS) {
        ExFreePool(switchObject);
        return status;
    }

    return NDIS_STATUS_SUCCESS;
}

VOID
FilterDetach(NDIS_HANDLE FilterModuleContext)
{
    PSWITCH_OBJECT switchObject = (PSWITCH_OBJECT)FilterModuleContext;

    KeMemoryBarrier();
    while(switchObject->PendingOidCount > 0)
    {
        NdisMSleep(1000);
    }

    ASSERTMSG("Trying to delete another switch than currently active", switchObject == VrSwitchObject);

    UninitializeVRouter(switchObject->ExtensionContext);
    UninitializeWindowsComponents(switchObject->ExtensionContext);

    VrSwitchObject = NULL;

    ExFreePool(switchObject);
}

NDIS_STATUS
FilterPause(NDIS_HANDLE FilterModuleContext, PNDIS_FILTER_PAUSE_PARAMETERS PauseParameters)
{
    PSWITCH_OBJECT switchObject = (PSWITCH_OBJECT)(FilterModuleContext);

    UNREFERENCED_PARAMETER(PauseParameters);

    switchObject->Running = FALSE;

    return NDIS_STATUS_SUCCESS;
}

NDIS_STATUS
FilterRestart(NDIS_HANDLE FilterModuleContext, PNDIS_FILTER_RESTART_PARAMETERS RestartParameters)
{
    PSWITCH_OBJECT switchObject = (PSWITCH_OBJECT)FilterModuleContext;
    NDIS_STATUS status;

    UNREFERENCED_PARAMETER(RestartParameters);

    PNDIS_SWITCH_PARAMETERS switchParameters;
    status = VrGetSwitchParameters(switchObject, &switchParameters);
    if (status != NDIS_STATUS_SUCCESS)
        return status;

    if (switchParameters->IsActive)
        status = HandleBasicNics(switchObject);

    VrFreeNdisObject(switchParameters);

    if (status == NDIS_STATUS_SUCCESS)
        switchObject->Running = TRUE;

    return status;
}

NDIS_STATUS
FilterNetPnpEvent(
    NDIS_HANDLE FilterModuleContext,
    PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification)
{
    PSWITCH_OBJECT switchObject = (PSWITCH_OBJECT)FilterModuleContext;

    if (NetPnPEventNotification->NetPnPEvent.NetEvent == NetEventSwitchActivate) {
        // Return value of HandleBasicNics must be ignored, because returning anything other than
        // NDIS_STATUS_SUCCESS breaks the overlying drivers. As a result, switch cannot be removed.
        // TODO: Add failure handling of HandleBasicNics to FilterRestart handler.
        HandleBasicNics(switchObject);
    }

    return NdisFNetPnPEvent(switchObject->NdisFilterHandle, NetPnPEventNotification);
}

VOID
BasicNicsClean(void)
{
    ExternalNicEntry.IsConnected = FALSE;
    VhostNicEntry.IsConnected = FALSE;
}

NDIS_STATUS
HandleBasicNics(PSWITCH_OBJECT SwitchObject)
{
    NDIS_STATUS status;
    PNDIS_SWITCH_NIC_ARRAY array;
    PNDIS_SWITCH_NIC_PARAMETERS curNic;
    ULONG arrIndex;

    status = VrGetNicArray(SwitchObject, &array);
    if (status != NDIS_STATUS_SUCCESS)
        return status;

    for (arrIndex = 0; arrIndex < array->NumElements; ++arrIndex) {
        curNic = NDIS_SWITCH_NIC_AT_ARRAY_INDEX(array, arrIndex);
        win_if_lock();
        HandleBasicNic(curNic);
        win_if_unlock();
    }
    VrFreeNdisObject(array);

    return NDIS_STATUS_SUCCESS;
}

static BOOLEAN
doesIfCountedStringStartWithUnicodeString(PIF_COUNTED_STRING_LH s, PUNICODE_STRING prefix)
{
    if (s->Length >= prefix->Length) {
        SIZE_T length = prefix->Length;
        return (RtlCompareMemory(s->String, prefix->Buffer, length) == length);
    }
    else
        return false;
}

static BOOLEAN
isContainerNic(PNDIS_SWITCH_NIC_PARAMETERS NicParams)
{
    UNICODE_STRING containerPrefix = RTL_CONSTANT_STRING(L"Container");
    return doesIfCountedStringStartWithUnicodeString(&NicParams->NicFriendlyName, &containerPrefix);
}

VOID
HandleBasicNic(PNDIS_SWITCH_NIC_PARAMETERS NicParams)
{
    if (NicParams->NicType == NdisSwitchNicTypeExternal && NicParams->NicIndex != 0 && !ExternalNicEntry.IsConnected) {
        ExternalNicEntry.PortId = NicParams->PortId;
        ExternalNicEntry.NicIndex = NicParams->NicIndex;
        ExternalNicEntry.IsConnected = TRUE;
    } else if (NicParams->NicType == NdisSwitchNicTypeInternal) {
        if (isContainerNic(NicParams)) {
            struct vr_interface *vif = GetVrInterfaceByGuid(NicParams->NetCfgInstanceId);
            if (vif) {
                vif->vif_port = NicParams->PortId;
                vif->vif_nic = NicParams->NicIndex;
                vif->vif_mtu = NicParams->MTU;
            }
        } else if (!VhostNicEntry.IsConnected) {
            VhostNicEntry.PortId = NicParams->PortId;
            VhostNicEntry.NicIndex = NicParams->NicIndex;
            VhostNicEntry.IsConnected = TRUE;
        }
    }
}
