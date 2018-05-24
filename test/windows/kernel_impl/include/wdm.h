/*
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#pragma once

#include "ntddk.h"
#include "ntstrsafe.h"

#include <windows.h>

// fake types

// Flags for DbgPrintEx

#define DPFLTR_ERROR_LEVEL 0
#define DPFLTR_WARNING_LEVEL 1
#define DPFLTR_TRACE_LEVEL 2
#define DPFLTR_INFO_LEVEL 3

#define DPFLTR_IHVNETWORK_ID 0

#define DO_DIRECT_IO 0
#define PAGE_SHIFT 0

#define MmGetSystemAddressForMdlSafe(_mdl, _flags) NULL
#define MmGetMdlByteCount(_mdl) 0

enum {
    IRP_MJ_CREATE,
    IRP_MJ_CLEANUP,
    IRP_MJ_CLOSE,
    IRP_MJ_WRITE,
    IRP_MJ_READ,
    IRP_MJ_DEVICE_CONTROL,
    IRP_MJ_MAXIMUM_FUNCTION,
};

typedef void *PDRIVER_DISPATCH;
typedef void *PDRIVER_UNLOAD;

typedef struct _MDL {
    struct _MDL *Next;
} MDL, *PMDL;

typedef struct _DEVICE_OBJECT {
    ULONG                       Flags;
} DEVICE_OBJECT, *PDEVICE_OBJECT;

typedef struct _DRIVER_OBJECT {
    PDRIVER_UNLOAD     DriverUnload;
} DRIVER_OBJECT, *PDRIVER_OBJECT;

typedef VOID *PEXT_DELETE_CALLBACK;
typedef VOID *PEX_TIMER;
typedef VOID *PEXT_CALLBACK;

// real types

typedef enum _POOL_TYPE {
    NonPagedPool,
    NonPagedPoolExecute                   = NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed               = NonPagedPool + 2,
    DontUseThisType,
    NonPagedPoolCacheAligned              = NonPagedPool + 4,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS         = NonPagedPool + 6,
    MaxPoolType,
    NonPagedPoolBase                      = 0,
    NonPagedPoolBaseMustSucceed           = NonPagedPoolBase + 2,
    NonPagedPoolBaseCacheAligned          = NonPagedPoolBase + 4,
    NonPagedPoolBaseCacheAlignedMustS     = NonPagedPoolBase + 6,
    NonPagedPoolSession                   = 32,
    PagedPoolSession                      = NonPagedPoolSession + 1,
    NonPagedPoolMustSucceedSession        = PagedPoolSession + 1,
    DontUseThisTypeSession                = NonPagedPoolMustSucceedSession + 1,
    NonPagedPoolCacheAlignedSession       = DontUseThisTypeSession + 1,
    PagedPoolCacheAlignedSession          = NonPagedPoolCacheAlignedSession + 1,
    NonPagedPoolCacheAlignedMustSSession  = PagedPoolCacheAlignedSession + 1,
    NonPagedPoolNx                        = 512,
    NonPagedPoolNxCacheAligned            = NonPagedPoolNx + 4,
    NonPagedPoolSessionNx                 = NonPagedPoolNx + 32
} POOL_TYPE;

typedef struct _EXT_DELETE_PARAMETERS {
  ULONG                Version;
  ULONG                Reserved;
  PEXT_DELETE_CALLBACK DeleteCallback;
  PVOID                DeleteContext;
} EXT_DELETE_PARAMETERS, *PEXT_DELETE_PARAMETERS;

typedef NTSTATUS DRIVER_INITIALIZE(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
);

typedef VOID DRIVER_UNLOAD(
    DRIVER_OBJECT *DriverObject
);

PVOID ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag);
VOID ExFreePool(PVOID P);
USHORT RtlUshortByteSwap(USHORT Source);
ULONG RtlUlongByteSwap(ULONG Source);

// Flag stub
#define EX_TIMER_HIGH_RESOLUTION 0
PEX_TIMER ExAllocateTimer(
  PEXT_CALLBACK Callback,
  PVOID         CallbackContext,
  ULONG         Attributes
);
