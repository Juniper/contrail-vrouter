/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include "windows_devices.h"
#include "vr_ksync_user.h"
#include "vr_ksync_kernel.h"
#include "vr_genetlink.h"
#include "vr_message.h"

const WCHAR KsyncDeviceName[]    = L"\\Device\\vrouterKsync";
const WCHAR KsyncDeviceSymLink[] = L"\\DosDevices\\vrouterKsync";

static PDEVICE_OBJECT KsyncDeviceObject   = NULL;
static NDIS_HANDLE    KsyncDeviceHandle   = NULL;

static void
KsyncAttachContextToFileContext(PKSYNC_DEVICE_CONTEXT ctx, PIRP irp)
{
    PIO_STACK_LOCATION io_stack = IoGetCurrentIrpStackLocation(irp);
    PFILE_OBJECT file_obj = io_stack->FileObject;
    file_obj->FsContext = ctx;
}

static PKSYNC_DEVICE_CONTEXT
KSyncGetContextFromFileContext(PIRP irp)
{
    PIO_STACK_LOCATION io_stack = IoGetCurrentIrpStackLocation(irp);
    PFILE_OBJECT file_obj = io_stack->FileObject;
    return file_obj->FsContext;
}

static inline NTSTATUS
KSyncCompleteIrp(PIRP Irp, NTSTATUS Status, ULONG Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS
KsyncDispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PKSYNC_DEVICE_CONTEXT ctx = KsyncAllocContext();
    if (ctx == NULL) {
        return KSyncCompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
    }
    KsyncAttachContextToFileContext(ctx, Irp);

    return KSyncCompleteIrp(Irp, STATUS_SUCCESS, FILE_OPENED);
}

NTSTATUS
KsyncDispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PKSYNC_DEVICE_CONTEXT ctx = KSyncGetContextFromFileContext(Irp);
    ASSERTMSG("KSync device context was not set", ctx != NULL);

    PKSYNC_RESPONSE response = KsyncPopResponse(ctx);
    while (response != NULL) {
        KsyncResponseDelete(response);
        response = KsyncPopResponse(ctx);
    }

    ExFreePool(ctx);
    return KSyncCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS
KsyncDispatchCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    return KSyncCompleteIrp(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS
KsyncDispatchWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PKSYNC_DEVICE_CONTEXT ctx = KSyncGetContextFromFileContext(Irp);
    ASSERT(ctx != NULL);

    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG userBufferSize = irpStack->Parameters.Write.Length;
    PMDL userBufferMdl = Irp->MdlAddress;
    if (userBufferSize == 0 || userBufferMdl == NULL) {
        return KSyncCompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    PCHAR userBuffer = MmGetSystemAddressForMdlSafe(userBufferMdl, LowPagePriority | MdlMappingNoExecute);
    if (userBuffer == NULL) {
        return KSyncCompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
    }

    RESULT_STATUS_INFO result =
        KsyncParseAndHandleWrite(ctx, userBuffer, userBufferSize);

    return KSyncCompleteIrp(Irp, result.Status, result.Information);
}

NTSTATUS
KsyncDispatchRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PKSYNC_DEVICE_CONTEXT ctx = KSyncGetContextFromFileContext(Irp);
    ASSERT(ctx != NULL);

    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG userBufferSize = irpStack->Parameters.Read.Length;
    PMDL userBufferMdl = Irp->MdlAddress;
    if (userBufferSize == 0 || userBufferMdl == NULL) {
        return KSyncCompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    PCHAR userBuffer = MmGetSystemAddressForMdlSafe(userBufferMdl, LowPagePriority | MdlMappingNoExecute);
    if (userBuffer == NULL) {
        return KSyncCompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
    }

    PKSYNC_RESPONSE resp = KsyncPopResponse(ctx);
    if (resp == NULL) {
        return KSyncCompleteIrp(Irp, STATUS_SUCCESS, 0);
    }

    if (resp->message_len <= userBufferSize) {
        ULONG dataSize = resp->message_len;
        RtlCopyMemory(userBuffer, resp->buffer, dataSize);
        KsyncResponseDelete(resp);
        return KSyncCompleteIrp(Irp, STATUS_SUCCESS, dataSize);
    } else {
        KsyncPrependResponse(ctx, resp);
        return KSyncCompleteIrp(Irp, STATUS_BUFFER_TOO_SMALL, 0);
    }
}

NTSTATUS
KsyncDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    return KSyncCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

NTSTATUS
KsyncCreateDevice(NDIS_HANDLE DriverHandle)
{
    VR_DEVICE_DISPATCH_CALLBACKS callbacks = {
        .create         = KsyncDispatchCreate,
        .cleanup        = KsyncDispatchCleanup,
        .close          = KsyncDispatchClose,
        .write          = KsyncDispatchWrite,
        .read           = KsyncDispatchRead,
        .device_control = KsyncDispatchDeviceControl,
    };

    return VRouterSetUpNamedDevice(DriverHandle, KsyncDeviceName, KsyncDeviceSymLink,
                                   &callbacks, &KsyncDeviceObject, &KsyncDeviceHandle);
}

VOID
KsyncDestroyDevice(VOID)
{
    VRouterTearDownNamedDevice(&KsyncDeviceHandle);
}
