/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_packet.h"
#include "vrouter.h"
#include "windows_devices.h"
#include "windows_nbl.h"

struct pkt0_context {
    LIST_ENTRY pkt_read_queue;
    LIST_ENTRY irp_read_queue;
    LIST_ENTRY irp_write_queue;
    BOOLEAN closing;
};

static const ULONG pkt0_allocation_tag = '0TKP';

static const WCHAR Pkt0DeviceName[]    = L"\\Device\\vrouterPkt0";
static const WCHAR Pkt0DeviceSymLink[] = L"\\DosDevices\\vrouterPkt0";

static PDEVICE_OBJECT Pkt0DeviceObject   = NULL;
static NDIS_HANDLE    Pkt0DeviceHandle   = NULL;

static KSPIN_LOCK Pkt0ContextLock;
static struct pkt0_context *Pkt0Context = NULL;

static struct pkt0_packet *alloc_pkt0_packet(struct vr_packet *vrp);
static void free_pkt0_packet(struct pkt0_packet * packet);

static IO_WORKITEM_ROUTINE_EX Pkt0DeferredWrite;

/* Used to notify vRouter that Agent might be dead */
extern volatile bool agent_alive;
extern void vhost_xconnect();

VOID
Pkt0Init(VOID)
{
    KeInitializeSpinLock(&Pkt0ContextLock);
}

static NTSTATUS
Pkt0CompleteIrp(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static VOID
Pkt0FinalizeIrpQueue(PLIST_ENTRY IrpQueue)
{
    PLIST_ENTRY entry;
    PIRP irp;

    while (!IsListEmpty(IrpQueue)) {
        entry = RemoveHeadList(IrpQueue);
        irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        Pkt0CompleteIrp(irp, STATUS_PIPE_CLOSING, 0);
    }
}

static NTSTATUS
Pkt0DispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    struct pkt0_context *ctx;
    KIRQL old_irql;

    ctx = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*ctx), pkt0_allocation_tag);
    if (ctx == NULL) {
        return Pkt0CompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
    }

    ctx->closing = FALSE;
    InitializeListHead(&ctx->pkt_read_queue);
    InitializeListHead(&ctx->irp_read_queue);
    InitializeListHead(&ctx->irp_write_queue);

    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(&Pkt0ContextLock, &old_irql);
    if (Pkt0Context != NULL) {
        status = STATUS_RESOURCE_IN_USE;
    } else {
        Pkt0Context = ctx;
    }
    KeReleaseSpinLock(&Pkt0ContextLock, old_irql);

    if (!NT_SUCCESS(status)) {
        ExFreePool(ctx);
        return Pkt0CompleteIrp(Irp, status, 0);
    }

    return Pkt0CompleteIrp(Irp, STATUS_SUCCESS, FILE_OPENED);
}

static NTSTATUS
Pkt0DispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    KIRQL old_irql;
    PLIST_ENTRY entry;
    struct pkt0_packet *packet;

    KeAcquireSpinLock(&Pkt0ContextLock, &old_irql);
    while (!IsListEmpty(&Pkt0Context->pkt_read_queue)) {
        entry = RemoveHeadList(&Pkt0Context->pkt_read_queue);
        packet = CONTAINING_RECORD(entry, struct pkt0_packet, list_entry);
        free_pkt0_packet(packet);
    }

    ExFreePool(Pkt0Context);
    Pkt0Context = NULL;
    KeReleaseSpinLock(&Pkt0ContextLock, old_irql);

    return Pkt0CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS
Pkt0DispatchCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    KIRQL old_irql;

    KeAcquireSpinLock(&Pkt0ContextLock, &old_irql);
    Pkt0FinalizeIrpQueue(&Pkt0Context->irp_read_queue);
    Pkt0FinalizeIrpQueue(&Pkt0Context->irp_write_queue);
    Pkt0Context->closing = TRUE;
    KeReleaseSpinLock(&Pkt0ContextLock, old_irql);

    /* Notify vRouter that agent might be dead */
    agent_alive = false;
    vhost_xconnect();

    return Pkt0CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

static VOID
Pkt0DeferredWrite(_In_ PVOID IoObject,
                  _In_opt_ PVOID Context,
                  _In_ PIO_WORKITEM WorkItem)
{
    PDEVICE_OBJECT device_object = IoObject;
    PLIST_ENTRY entry = NULL;
    PIRP irp = NULL;
    PIO_STACK_LOCATION io_stack;
    ULONG count;
    unsigned char *data = NULL;
    unsigned char *pkt_data = NULL;
    KIRQL old_irql;

    struct vrouter *router = vrouter_get(0);
    struct vr_interface *agent_if;
    struct vr_packet *pkt = NULL;

    KeAcquireSpinLock(&Pkt0ContextLock, &old_irql);
    if (Pkt0Context != NULL && !IsListEmpty(&Pkt0Context->irp_write_queue)) {
        entry = RemoveHeadList(&Pkt0Context->irp_write_queue);
        irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
    }
    KeReleaseSpinLock(&Pkt0ContextLock, old_irql);
    if (irp == NULL)
        goto fail;

    agent_if = router->vr_agent_if;
    if (agent_if == NULL)
        goto fail;

    io_stack = IoGetCurrentIrpStackLocation(irp);
    count = io_stack->Parameters.Write.Length;
    data = MmGetSystemAddressForMdlSafe(irp->MdlAddress, LowPagePriority | MdlMappingNoExecute);
    if (data == NULL)
        goto fail;

    pkt_data = ExAllocatePoolWithTag(NonPagedPoolNx, count, pkt0_allocation_tag);
    if (pkt_data == NULL)
        goto fail;

    RtlCopyMemory(pkt_data, data, count);

    pkt = win_allocate_packet(pkt_data, count);
    if (pkt == NULL)
        goto fail;
    pkt->vp_if = agent_if;

    Pkt0CompleteIrp(irp, STATUS_SUCCESS, count);

    agent_if->vif_rx(agent_if, pkt, VLAN_ID_INVALID);

    IoFreeWorkItem(WorkItem);
    return;

fail:
    if (pkt_data) {
        ExFreePool(pkt_data);
    }
    if (irp) {
        Pkt0CompleteIrp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
    }
    IoFreeWorkItem(WorkItem);
    return;
}

static NTSTATUS
Pkt0DispatchWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_WORKITEM work_item;
    KIRQL old_irql;
    NTSTATUS status;

    work_item = IoAllocateWorkItem(DeviceObject);
    if (work_item == NULL) {
        return Pkt0CompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
    }

    KeAcquireSpinLock(&Pkt0ContextLock, &old_irql);
    if (Pkt0Context->closing) {
        status = Pkt0CompleteIrp(Irp, STATUS_PIPE_CLOSING, 0);
    } else {
        InsertTailList(&Pkt0Context->irp_write_queue, &Irp->Tail.Overlay.ListEntry);
        IoMarkIrpPending(Irp);
        status = STATUS_PENDING;
    }
    KeReleaseSpinLock(&Pkt0ContextLock, old_irql);

    if (status == STATUS_PENDING) {
        IoQueueWorkItemEx(work_item, Pkt0DeferredWrite, DelayedWorkQueue, NULL);
    } else {
        IoFreeWorkItem(work_item);
    }

    return status;
}

static NTSTATUS
Pkt0TransferPacketToUser(PIRP Irp, struct pkt0_packet *packet)
{
    PIO_STACK_LOCATION io_stack;
    PVOID buffer;
    NTSTATUS ret;

    io_stack = IoGetCurrentIrpStackLocation(Irp);
    buffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, LowPagePriority | MdlMappingNoExecute);
    if (buffer != NULL) {
        ASSERTMSG("Read buffer too short", io_stack->Parameters.Read.Length >= packet->length);
        RtlCopyMemory(buffer, packet->buffer, packet->length);
        ret = Pkt0CompleteIrp(Irp, STATUS_SUCCESS, packet->length);
    } else {
        ret = Pkt0CompleteIrp(Irp, STATUS_INSUFFICIENT_RESOURCES, 0);
    }
    free_pkt0_packet(packet);

    return ret;
}

static NTSTATUS
Pkt0DispatchRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    struct pkt0_packet *pkt = NULL;
    KIRQL old_irql;
    PLIST_ENTRY entry;
    NTSTATUS status;

    KeAcquireSpinLock(&Pkt0ContextLock, &old_irql);
    if (Pkt0Context->closing) {
        status = Pkt0CompleteIrp(Irp, STATUS_PIPE_CLOSING, 0);
    } else if (IsListEmpty(&Pkt0Context->pkt_read_queue)) {
        InsertTailList(&Pkt0Context->irp_read_queue, &Irp->Tail.Overlay.ListEntry);
        IoMarkIrpPending(Irp);
        status = STATUS_PENDING;
    } else {
        entry = RemoveHeadList(&Pkt0Context->pkt_read_queue);
        pkt = CONTAINING_RECORD(entry, struct pkt0_packet, list_entry);
    }
    KeReleaseSpinLock(&Pkt0ContextLock, old_irql);

    if (pkt != NULL) {
        status = Pkt0TransferPacketToUser(Irp, pkt);
    }

    return status;
}

static NTSTATUS
Pkt0DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return Pkt0CompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
}

NTSTATUS
Pkt0CreateDevice(NDIS_HANDLE DriverHandle)
{
    if (Pkt0Context != NULL) {
        return STATUS_RESOURCE_IN_USE;
    }

    VR_DEVICE_DISPATCH_CALLBACKS callbacks = {
        .create         = Pkt0DispatchCreate,
        .cleanup        = Pkt0DispatchCleanup,
        .close          = Pkt0DispatchClose,
        .write          = Pkt0DispatchWrite,
        .read           = Pkt0DispatchRead,
        .device_control = Pkt0DispatchDeviceControl,
    };

    return VRouterSetUpNamedDevice(DriverHandle, Pkt0DeviceName, Pkt0DeviceSymLink,
                                   &callbacks, &Pkt0DeviceObject, &Pkt0DeviceHandle);
}

VOID
Pkt0DestroyDevice(VOID)
{
    KIRQL old_irql;

    VRouterTearDownNamedDevice(&Pkt0DeviceHandle);

    KeAcquireSpinLock(&Pkt0ContextLock, &old_irql);
    if (Pkt0Context != NULL) {
        Pkt0FinalizeIrpQueue(&Pkt0Context->irp_read_queue);
        Pkt0FinalizeIrpQueue(&Pkt0Context->irp_write_queue);
        Pkt0Context->closing = TRUE;
    }
    KeReleaseSpinLock(&Pkt0ContextLock, old_irql);
}

/*
 * Functions called from dp-core
 */

static struct pkt0_packet *
alloc_pkt0_packet(struct vr_packet *vrp)
{
    struct pkt0_packet *packet;
    unsigned int pkt_size = pkt_len(vrp);
    int ret;

    packet = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(struct pkt0_packet), pkt0_allocation_tag);
    if (packet == NULL)
        return NULL;
    RtlZeroMemory(packet, sizeof(*packet));

    packet->buffer = ExAllocatePoolWithTag(NonPagedPoolNx, pkt_size, pkt0_allocation_tag);
    if (packet->buffer == NULL)
        goto failure;
    RtlZeroMemory(packet->buffer, pkt_size);

    ret = vr_pcopy(packet->buffer, vrp, vrp->vp_data, pkt_size);
    if (ret != pkt_size) {
        goto failure;
    }
    packet->length = ret;

    return packet;

failure:
    if (packet)
        free_pkt0_packet(packet);

    return NULL;
}

static void
free_pkt0_packet(struct pkt0_packet *packet)
{
    if (packet->buffer)
        ExFreePoolWithTag(packet->buffer, pkt0_allocation_tag);

    ExFreePool(packet);
}

int
pkt0_if_tx(struct vr_interface *vif, struct vr_packet *vrp)
{
    KIRQL old_irql;
    PLIST_ENTRY entry;
    PIRP irp = NULL;
    struct pkt0_packet *pkt;

    pkt = alloc_pkt0_packet(vrp);
    if (pkt == NULL)
        return 0;

    KeAcquireSpinLock(&Pkt0ContextLock, &old_irql);
    if (Pkt0Context != NULL) {
        if (IsListEmpty(&Pkt0Context->irp_read_queue)) {
            InsertTailList(&Pkt0Context->pkt_read_queue, &pkt->list_entry);
        } else {
            entry = RemoveHeadList(&Pkt0Context->irp_read_queue);
            irp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        }
    } else {
        free_pkt0_packet(pkt);
    }
    KeReleaseSpinLock(&Pkt0ContextLock, old_irql);

    if (irp != NULL) {
        Pkt0TransferPacketToUser(irp, pkt);
    }

    /* vr_packet is no longer needed, drop it without updating statistics */
    win_free_packet(vrp);

    return 0;
}
