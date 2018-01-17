/*
 * windows_devices.h -- definitions used in pipe handling on Windows
 *
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WINDOWS_DEVICES_H__
#define __WINDOWS_DEVICES_H__

#include "vr_os.h"
#include "vr_windows.h"

struct _VR_DEVICE_DISPATCH_CALLBACKS {
    PDRIVER_DISPATCH create;
    PDRIVER_DISPATCH close;
    PDRIVER_DISPATCH cleanup;
    PDRIVER_DISPATCH write;
    PDRIVER_DISPATCH read;
    PDRIVER_DISPATCH device_control;
};

typedef struct _VR_DEVICE_DISPATCH_CALLBACKS VR_DEVICE_DISPATCH_CALLBACKS;
typedef struct _VR_DEVICE_DISPATCH_CALLBACKS *PVR_DEVICE_DISPATCH_CALLBACKS;

NTSTATUS KsyncCreateDevice(NDIS_HANDLE DriverHandle);
VOID KsyncDestroyDevice(VOID);

VOID Pkt0Init(VOID);
NTSTATUS Pkt0CreateDevice(NDIS_HANDLE DriverHandle);
VOID Pkt0DestroyDevice(VOID);

NTSTATUS ShmemCreateDevices(NDIS_HANDLE DriverHandle);
VOID ShmemDestroyDevices(VOID);

NTSTATUS VRouterSetUpNamedDevice(NDIS_HANDLE DriverHandle,
                                 PCWSTR DeviceName,
                                 PCWSTR DeviceSymlink,
                                 PVR_DEVICE_DISPATCH_CALLBACKS Callbacks,
                                 PDEVICE_OBJECT *DeviceObject,
                                 NDIS_HANDLE *DeviceHandle);
VOID VRouterTearDownNamedDevice(NDIS_HANDLE *DeviceHandle);

/*
 * Pkt0 related definitions
 */
struct pkt0_packet {
    uint8_t *buffer;
    size_t length;
    LIST_ENTRY list_entry;
};

int pkt0_if_tx(struct vr_interface *vif, struct vr_packet *pkt);

/*
 * Flow device related definitions
 */
struct _SHMEM_DEVICE_CONTEXT {
    PVOID UserVirtualAddress;
    PMDL MemoryMdl;
};

typedef struct _SHMEM_DEVICE_CONTEXT   SHMEM_DEVICE_CONTEXT;
typedef struct _SHMEM_DEVICE_CONTEXT *PSHMEM_DEVICE_CONTEXT;

#endif /* __WINDOWS_DEVICES_H__ */
