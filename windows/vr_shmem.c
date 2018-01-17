/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include "precomp.h"
#include "windows_shmem.h"

#include "vrouter.h"
#include "vr_flow.h"

extern void *vr_flow_table, *vr_oflow_table;
extern void *vr_bridge_table, *vr_bridge_otable;

struct _SHMEM_PARAMS {
    PVOID  Block;
    size_t Size;
    PMDL   Mdl;
    PVOID *VrouterTablePtr;
    PVOID *VrouterOtablePtr;
};
typedef struct _SHMEM_PARAMS SHMEM_PARAMS;

static ULONG ShmemAllocationTag = 'MSRV';
static SHMEM_PARAMS FlowParams;
static SHMEM_PARAMS BridgeParams;

static NTSTATUS SingularShmemInit(SHMEM_PARAMS *const, const size_t, const size_t);
static VOID SingularShmemExit(SHMEM_PARAMS *const);
static VOID SingularShmemClean(SHMEM_PARAMS *const);

static NTSTATUS
SingularShmemInit(SHMEM_PARAMS *const Params, const size_t VrouterTableSize, const size_t VrouterOtableSize)
{
    ASSERT(Params->Block == NULL);
    ASSERT(Params->Mdl == NULL);

    NDIS_STATUS status;

    Params->Size = VrouterTableSize + VrouterOtableSize;
    Params->Block = ExAllocatePoolWithTag(NonPagedPoolNx, Params->Size, ShmemAllocationTag);
    if (Params->Block == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    Params->Mdl = IoAllocateMdl(Params->Block, Params->Size, FALSE, FALSE, NULL);
    if (Params->Mdl == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    MmBuildMdlForNonPagedPool(Params->Mdl);

    *(Params->VrouterTablePtr) = Params->Block;
    *(Params->VrouterOtablePtr) = (uint8_t *)(Params->Block) + VrouterTableSize;

    return STATUS_SUCCESS;

Cleanup:
    SingularShmemExit(Params);
    return status;
}

static VOID
SingularShmemExit(SHMEM_PARAMS *const Params)
{
    *(Params->VrouterTablePtr) = NULL;
    *(Params->VrouterOtablePtr) = NULL;

    if (Params->Mdl != NULL) {
        IoFreeMdl(Params->Mdl);
        Params->Mdl = NULL;
    }

    if (Params->Block != NULL) {
        ExFreePool(Params->Block);
        Params->Block = NULL;
    }
}

static VOID
SingularShmemClean(SHMEM_PARAMS *const Params)
{
    ASSERT(Params->Block != NULL);
    ASSERT(Params->Size > 0);

    RtlZeroMemory(Params->Block, Params->Size);
}

PMDL
GetFlowMemoryMdl(VOID)
{
    return FlowParams.Mdl;
}

PMDL
GetBridgeMemoryMdl(VOID)
{
    return BridgeParams.Mdl;
}

NTSTATUS
ShmemInit(VOID)
{
    NDIS_STATUS status;

    FlowParams.VrouterTablePtr = &vr_flow_table;
    FlowParams.VrouterOtablePtr = &vr_oflow_table;
    vr_compute_size_oflow_table();
    status = SingularShmemInit(&FlowParams, VR_FLOW_TABLE_SIZE, VR_OFLOW_TABLE_SIZE);
    if (!NT_SUCCESS(status))
        return status;

    BridgeParams.VrouterTablePtr = &vr_bridge_table;
    BridgeParams.VrouterOtablePtr = &vr_bridge_otable;
    vr_compute_size_bridge_otable();
    return SingularShmemInit(&BridgeParams, VR_BRIDGE_TABLE_SIZE, VR_BRIDGE_OFLOW_TABLE_SIZE);
}

VOID
ShmemExit(VOID)
{
    SingularShmemExit(&FlowParams);
    SingularShmemExit(&BridgeParams);
}

VOID
ShmemClean(VOID)
{
    SingularShmemClean(&FlowParams);
    SingularShmemClean(&BridgeParams);
}
