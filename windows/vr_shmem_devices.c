/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include "precomp.h"

#include "windows_devices.h"
#include "windows_flow_ioctl.h"
#include "windows_ksync.h"
#include "windows_mem.h"

static const WCHAR FlowDeviceName[]    = L"\\Device\\vrouterFlow";
static const WCHAR FlowDeviceSymLink[] = L"\\DosDevices\\vrouterFlow";

static PDEVICE_OBJECT FlowDeviceObject   = NULL;
static NDIS_HANDLE    FlowDeviceHandle   = NULL;

static ULONG FlowAllocationTag = 'LFRV';

static PFLOW_DEVICE_CONTEXT
FlowAllocateContext()
{
    PFLOW_DEVICE_CONTEXT ctx;

    ctx = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*ctx), FlowAllocationTag);
    if (ctx == NULL)
        return NULL;

    ctx->UserVirtualAddress = NULL;

    return ctx;
}

static VOID
FlowFreeContext(PFLOW_DEVICE_CONTEXT ctx)
{
    if (ctx != NULL) {
        ExFreePool(ctx);
    }
}

static VOID
FlowAttachContextToFileContext(PFLOW_DEVICE_CONTEXT ctx, PIRP irp)
{
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(irp);
    PFILE_OBJECT fileObj = ioStack->FileObject;
    fileObj->FsContext = ctx;
}

static PFLOW_DEVICE_CONTEXT
FlowGetContextFromFileContext(PIRP irp)
{
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(irp);
    PFILE_OBJECT fileObj = ioStack->FileObject;
    return fileObj->FsContext;
}

static NTSTATUS
FlowCompleteIrp(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS
FlowDispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFLOW_DEVICE_CONTEXT ctx = FlowAllocateContext();
    if (ctx == NULL)
        goto Failure;
    FlowAttachContextToFileContext(ctx, Irp);

    PMDL flowMemoryMdl = GetFlowMemoryMdl();
    if (flowMemoryMdl == NULL)
        goto Failure;

    MM_PAGE_PRIORITY pagePriority = NormalPagePriority | MdlMappingNoExecute;
    PVOID userVirtualAddress = MmMapLockedPagesSpecifyCache(flowMemoryMdl,
                                                            UserMode,
                                                            MmNonCached,
                                                            NULL,
                                                            FALSE,
                                                            pagePriority);
    if (userVirtualAddress == NULL)
        goto Failure;

    ctx->UserVirtualAddress = userVirtualAddress;
    ctx->FlowMemoryMdl = flowMemoryMdl;

    return FlowCompleteIrp(Irp, STATUS_SUCCESS, (ULONG_PTR)(FILE_OPENED));

Failure:
    if (ctx != NULL) {
        FlowAttachContextToFileContext(NULL, Irp);
        FlowFreeContext(ctx);
    }

    return FlowCompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES, (ULONG_PTR)(0));
}

static NTSTATUS
FlowDispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFLOW_DEVICE_CONTEXT ctx = FlowGetContextFromFileContext(Irp);

    ASSERT(ctx != NULL);
    ASSERT(ctx->UserVirtualAddress != NULL);
    ASSERT(ctx->FlowMemoryMdl != NULL);

    MmUnmapLockedPages(ctx->UserVirtualAddress, ctx->FlowMemoryMdl);
    FlowAttachContextToFileContext(NULL, Irp);
    FlowFreeContext(ctx);

    return FlowCompleteIrp(Irp, STATUS_SUCCESS, (ULONG_PTR)(0));
}

static NTSTATUS
FlowDispatchCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    return FlowCompleteIrp(Irp, STATUS_SUCCESS, (ULONG_PTR)(0));
}

static NTSTATUS
FlowHandleGetAddress(PDEVICE_OBJECT DeviceObject,
                     PIRP Irp,
                     PFLOW_DEVICE_CONTEXT ctx)
{
    NTSTATUS status;

    PMDL bufferMdl = Irp->MdlAddress;
    ULONG expectedLength = sizeof(ctx->UserVirtualAddress);
    ULONG bufferLength = MmGetMdlByteCount(bufferMdl);
    if (bufferLength != expectedLength) {
        status = STATUS_INVALID_PARAMETER;
        goto Failure;
    }

    PVOID buffer = MmGetSystemAddressForMdlSafe(bufferMdl,
        NormalPagePriority | MdlMappingNoExecute);
    if (buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Failure;
    }
    RtlCopyMemory(buffer, &ctx->UserVirtualAddress, expectedLength);

    return FlowCompleteIrp(Irp, STATUS_SUCCESS, expectedLength);

Failure:
    return FlowCompleteIrp(Irp, status, (ULONG_PTR)(0));
}

static NTSTATUS
FlowDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION ioStack;
    PFLOW_DEVICE_CONTEXT ctx;
    PVOID buffer;

    ctx = FlowGetContextFromFileContext(Irp);
    ASSERT(ctx != NULL);

    ioStack = IoGetCurrentIrpStackLocation(Irp);
    switch (ioStack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_FLOW_GET_ADDRESS:
            return FlowHandleGetAddress(DeviceObject, Irp, ctx);
        default:
            return FlowCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, (ULONG_PTR)(0));
    }
}

static NTSTATUS
FlowDispatchRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    return FlowCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, (ULONG_PTR)(0));
}

static NTSTATUS
FlowDispatchWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    return FlowCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, (ULONG_PTR)(0));
}

NTSTATUS
FlowCreateDevice(NDIS_HANDLE DriverHandle)
{
    VR_DEVICE_DISPATCH_CALLBACKS callbacks = {
        .create         = FlowDispatchCreate,
        .cleanup        = FlowDispatchCleanup,
        .close          = FlowDispatchClose,
        .write          = FlowDispatchWrite,
        .read           = FlowDispatchRead,
        .device_control = FlowDispatchDeviceControl,
    };

    return VRouterSetUpNamedDevice(DriverHandle, FlowDeviceName, FlowDeviceSymLink,
                                   &callbacks, &FlowDeviceObject, &FlowDeviceHandle);
}

VOID
FlowDestroyDevice(VOID)
{
    VRouterTearDownNamedDevice(&FlowDeviceHandle);
}
