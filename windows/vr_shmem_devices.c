/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include "precomp.h"

#include "windows_devices.h"
#include "windows_shmem_ioctl.h"
#include "windows_ksync.h"
#include "windows_shmem.h"

static const WCHAR ShmemFlowDeviceName[]    = L"\\Device\\vrouterFlow";
static const WCHAR ShmemFlowDeviceSymLink[] = L"\\DosDevices\\vrouterFlow";
static PDEVICE_OBJECT ShmemFlowDeviceObject   = NULL;
static NDIS_HANDLE    ShmemFlowDeviceHandle   = NULL;

static const WCHAR ShmemBridgeDeviceName[]    = L"\\Device\\vrouterBridge";
static const WCHAR ShmemBridgeDeviceSymLink[] = L"\\DosDevices\\vrouterBridge";
static PDEVICE_OBJECT ShmemBridgeDeviceObject   = NULL;
static NDIS_HANDLE    ShmemBridgeDeviceHandle   = NULL;

static ULONG ShmemDeviceAllocationTag = 'DSRV';

static PSHMEM_DEVICE_CONTEXT
ShmemAllocateContext()
{
    PSHMEM_DEVICE_CONTEXT ctx;

    ctx = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*ctx), ShmemDeviceAllocationTag);
    if (ctx == NULL)
        return NULL;

    ctx->UserVirtualAddress = NULL;

    return ctx;
}

static VOID
ShmemFreeContext(PSHMEM_DEVICE_CONTEXT ctx)
{
    if (ctx != NULL) {
        ExFreePool(ctx);
    }
}

static VOID
ShmemAttachContextToFileContext(PSHMEM_DEVICE_CONTEXT ctx, PIRP irp)
{
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(irp);
    PFILE_OBJECT fileObj = ioStack->FileObject;
    fileObj->FsContext = ctx;
}

static PSHMEM_DEVICE_CONTEXT
ShmemGetContextFromFileContext(PIRP irp)
{
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(irp);
    PFILE_OBJECT fileObj = ioStack->FileObject;
    return fileObj->FsContext;
}

static NTSTATUS
ShmemCompleteIrp(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS
ShmemMapAddressForUserspace(PIRP Irp, PMDL MemoryMdl)
{
    PSHMEM_DEVICE_CONTEXT ctx = NULL;

    if (MemoryMdl == NULL)
        goto Failure;

    ctx = ShmemAllocateContext();
    if (ctx == NULL)
        goto Failure;
    ShmemAttachContextToFileContext(ctx, Irp);

    MM_PAGE_PRIORITY pagePriority = NormalPagePriority | MdlMappingNoExecute;
    PVOID userVirtualAddress = MmMapLockedPagesSpecifyCache(MemoryMdl, UserMode, MmNonCached, NULL,
        FALSE, pagePriority);
    if (userVirtualAddress == NULL)
        goto Failure;

    ctx->UserVirtualAddress = userVirtualAddress;
    ctx->MemoryMdl = MemoryMdl;
    return ShmemCompleteIrp(Irp, STATUS_SUCCESS, (ULONG_PTR)(FILE_OPENED));

Failure:
    if (ctx != NULL) {
        ShmemAttachContextToFileContext(NULL, Irp);
        ShmemFreeContext(ctx);
    }
    return ShmemCompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES, (ULONG_PTR)(0));
}

static NTSTATUS
FlowShmemDispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    return ShmemMapAddressForUserspace(Irp, GetFlowMemoryMdl());
}

static NTSTATUS
BridgeShmemDispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    return ShmemMapAddressForUserspace(Irp, GetBridgeMemoryMdl());
}

static NTSTATUS
ShmemDispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PSHMEM_DEVICE_CONTEXT ctx = ShmemGetContextFromFileContext(Irp);

    ASSERT(ctx != NULL);
    ASSERT(ctx->UserVirtualAddress != NULL);
    ASSERT(ctx->MemoryMdl != NULL);

    MmUnmapLockedPages(ctx->UserVirtualAddress, ctx->MemoryMdl);
    ShmemAttachContextToFileContext(NULL, Irp);
    ShmemFreeContext(ctx);

    return ShmemCompleteIrp(Irp, STATUS_SUCCESS, (ULONG_PTR)(0));
}

static NTSTATUS
ShmemDispatchCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    return ShmemCompleteIrp(Irp, STATUS_SUCCESS, (ULONG_PTR)(0));
}

static NTSTATUS
ShmemHandleGetAddress(PDEVICE_OBJECT DeviceObject, PIRP Irp, PSHMEM_DEVICE_CONTEXT ctx)
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

    return ShmemCompleteIrp(Irp, STATUS_SUCCESS, expectedLength);

Failure:
    return ShmemCompleteIrp(Irp, status, (ULONG_PTR)(0));
}

static NTSTATUS
ShmemDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION ioStack;
    PSHMEM_DEVICE_CONTEXT ctx;
    PVOID buffer;

    ctx = ShmemGetContextFromFileContext(Irp);
    ASSERT(ctx != NULL);

    ioStack = IoGetCurrentIrpStackLocation(Irp);
    switch (ioStack->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_SHMEM_GET_ADDRESS:
            return ShmemHandleGetAddress(DeviceObject, Irp, ctx);
        default:
            return ShmemCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, (ULONG_PTR)(0));
    }
}

static NTSTATUS
ShmemDispatchRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    return ShmemCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, (ULONG_PTR)(0));
}

static NTSTATUS
ShmemDispatchWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    return ShmemCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, (ULONG_PTR)(0));
}

NTSTATUS
ShmemCreateDevices(NDIS_HANDLE DriverHandle)
{
    NTSTATUS status;
    VR_DEVICE_DISPATCH_CALLBACKS callbacks = {
        .cleanup        = ShmemDispatchCleanup,
        .close          = ShmemDispatchClose,
        .write          = ShmemDispatchWrite,
        .read           = ShmemDispatchRead,
        .device_control = ShmemDispatchDeviceControl,
    };

    callbacks.create = FlowShmemDispatchCreate;
    status = VRouterSetUpNamedDevice(DriverHandle, ShmemFlowDeviceName, ShmemFlowDeviceSymLink,
        &callbacks, &ShmemFlowDeviceObject, &ShmemFlowDeviceHandle);
    if (!NT_SUCCESS(status))
        return status;

    callbacks.create = BridgeShmemDispatchCreate;
    status = VRouterSetUpNamedDevice(DriverHandle, ShmemBridgeDeviceName, ShmemBridgeDeviceSymLink,
        &callbacks, &ShmemBridgeDeviceObject, &ShmemBridgeDeviceHandle);
    if (!NT_SUCCESS(status))
        VRouterTearDownNamedDevice(&ShmemFlowDeviceHandle);

    return status;
}

VOID
ShmemDestroyDevices(VOID)
{
    VRouterTearDownNamedDevice(&ShmemFlowDeviceHandle);
    VRouterTearDownNamedDevice(&ShmemBridgeDeviceHandle);
}
