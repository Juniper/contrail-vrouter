/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include "precomp.h"
#include "windows_devices.h"

NTSTATUS
VRouterSetUpNamedDevice(NDIS_HANDLE DriverHandle,
                        PCWSTR DeviceName,
                        PCWSTR DeviceSymlink,
                        PVR_DEVICE_DISPATCH_CALLBACKS Callbacks,
                        PDEVICE_OBJECT *DeviceObject,
                        NDIS_HANDLE *DeviceHandle)
{
    NTSTATUS status;
    UNICODE_STRING device_name;
    UNICODE_STRING device_symlink;

    status = RtlUnicodeStringInit(&device_name, DeviceName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = RtlUnicodeStringInit(&device_symlink, DeviceSymlink);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PDRIVER_DISPATCH dispatch_table[IRP_MJ_MAXIMUM_FUNCTION + 1];
    NdisZeroMemory(dispatch_table, (IRP_MJ_MAXIMUM_FUNCTION + 1) * sizeof(PDRIVER_DISPATCH));

    dispatch_table[IRP_MJ_CREATE]         = Callbacks->create;
    dispatch_table[IRP_MJ_CLEANUP]        = Callbacks->cleanup;
    dispatch_table[IRP_MJ_CLOSE]          = Callbacks->close;
    dispatch_table[IRP_MJ_WRITE]          = Callbacks->write;
    dispatch_table[IRP_MJ_READ]           = Callbacks->read;
    dispatch_table[IRP_MJ_DEVICE_CONTROL] = Callbacks->device_control;

    NDIS_DEVICE_OBJECT_ATTRIBUTES attributes;
    NdisZeroMemory(&attributes, sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES));

    attributes.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
    attributes.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
    attributes.Header.Size = NDIS_SIZEOF_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;

    attributes.DeviceName = &device_name;
    attributes.SymbolicName = &device_symlink;
    attributes.MajorFunctions = &dispatch_table[0];
    attributes.ExtensionSize = 0;
    attributes.DefaultSDDLString = &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RWX_RES_RWX;
    attributes.DeviceClassGuid = NULL;

    status = NdisRegisterDeviceEx(DriverHandle, &attributes, DeviceObject, DeviceHandle);
    if (NT_SUCCESS(status)) {
        (*DeviceObject)->Flags |= DO_DIRECT_IO;
    }

    return status;
}

VOID
VRouterTearDownNamedDevice(NDIS_HANDLE *DeviceHandle)
{
    if (*DeviceHandle == NULL) {
        return;
    }

    NdisDeregisterDeviceEx(*DeviceHandle);
    *DeviceHandle = NULL;
}
