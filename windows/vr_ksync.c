/*
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#include "precomp.h"
#include "windows_ksync.h"

#include "vr_genetlink.h"
#include "vr_message.h"

#define NLA_DATA(nla)   ((char *)nla + NLA_HDRLEN)
#define NLA_LEN(nla)    (nla->nla_len - NLA_HDRLEN)

static ULONG KsyncAllocationTag = 'NYSK';

const WCHAR KsyncDeviceName[]    = L"\\Device\\vrouterKsync";
const WCHAR KsyncDeviceSymLink[] = L"\\DosDevices\\vrouterKsync";

static PDEVICE_OBJECT KsyncDeviceObject   = NULL;
static NDIS_HANDLE    KsyncDeviceHandle   = NULL;

static PKSYNC_DEVICE_CONTEXT
KSyncAllocContext()
{
    PKSYNC_DEVICE_CONTEXT ctx = ExAllocatePoolWithTag(NonPagedPoolNx,
                                                      sizeof(*ctx),
                                                      KsyncAllocationTag);
    if (ctx == NULL)
        return NULL;

    ctx->WrittenBytes = 0;
    ctx->WriteBufferSize = sizeof(ctx->WriteBuffer);
    RtlZeroMemory(ctx->WriteBuffer, ctx->WriteBufferSize);

    ctx->responses = NULL;

    return ctx;
}

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

static PKSYNC_RESPONSE
KsyncResponseCreate()
{
    PKSYNC_RESPONSE resp;

    resp = ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(*resp), KsyncAllocationTag);
    if (resp != NULL) {
        RtlZeroMemory(resp, sizeof(*resp));
    }

    return resp;
}

static VOID
KsyncResponseDelete(PKSYNC_RESPONSE resp)
{
    ASSERT(resp != NULL);

    ExFreePool(resp);
}

static VOID
KsyncAppendResponse(PKSYNC_DEVICE_CONTEXT ctx, PKSYNC_RESPONSE resp)
{
    PKSYNC_RESPONSE  elem;
    PKSYNC_RESPONSE *iter = &(ctx->responses);

    while (*iter != NULL) {
        elem = *iter;
        iter = &(elem->next);
    }

    *iter = resp;
}

static VOID
KsyncPrependResponse(PKSYNC_DEVICE_CONTEXT ctx, PKSYNC_RESPONSE resp)
{
    resp->next = ctx->responses;
    ctx->responses = resp;
}

static PKSYNC_RESPONSE
KsyncPopResponse(PKSYNC_DEVICE_CONTEXT ctx)
{
    PKSYNC_RESPONSE resp = ctx->responses;

    if (resp != NULL) {
        ctx->responses = resp->next;
        resp->next = NULL;
        return resp;
    } else {
        return NULL;
    }
}

static VOID
KsyncContextResetWriteBuffer(PKSYNC_DEVICE_CONTEXT ctx)
{
    ctx->WrittenBytes = 0;
    RtlZeroMemory(ctx->WriteBuffer, ctx->WriteBufferSize);
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
    PKSYNC_DEVICE_CONTEXT ctx = KSyncAllocContext();
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

static NTSTATUS
KsyncHandleWrite(PKSYNC_DEVICE_CONTEXT ctx, uint8_t *buffer, size_t buffer_size)
{
    struct vr_message request;
    struct vr_message *response;
    uint32_t multi_flag;
    int ret;

    /* Received buffer contains tightly packed Netlink headers, thus we can just
       increment appropriate headers */
    struct nlmsghdr   *nlh   = (struct nlmsghdr *)(buffer);
    struct genlmsghdr *genlh = (struct genlmsghdr *)(nlh + 1);
    struct nlattr     *nla   = (struct nlattr *)(genlh + 1);

    request.vr_message_buf = NLA_DATA(nla);
    request.vr_message_len = NLA_LEN(nla);

    ret = vr_message_request(&request);
    if (ret) {
        if (vr_send_response(ret)) {
            DbgPrint("%s: generating error response has failed\n", __func__);
            return STATUS_INVALID_PARAMETER;
        }
    }

    multi_flag = 0;
    while ((response = vr_message_dequeue_response())) {
        if (!multi_flag && !vr_response_queue_empty())
            multi_flag = NLM_F_MULTI;

        char *data = response->vr_message_buf - NETLINK_HEADER_LEN;
        size_t data_len = NLMSG_ALIGN(response->vr_message_len + NETLINK_HEADER_LEN);

        struct nlmsghdr *nlh_resp = (struct nlmsghdr *)(data);
        nlh_resp->nlmsg_len = data_len;
        nlh_resp->nlmsg_type = nlh->nlmsg_type;
        nlh_resp->nlmsg_flags = multi_flag;
        nlh_resp->nlmsg_seq = nlh->nlmsg_seq;
		nlh_resp->nlmsg_pid = 0;

        /* 'genlmsghdr' should be put directly after 'nlmsghdr', thus we can just
           increment previous header pointer */
        struct genlmsghdr *genlh_resp = (struct genlmsghdr *)(nlh_resp + 1);
        RtlCopyMemory(genlh_resp, genlh, sizeof(*genlh_resp));

        /* 'nlattr' should be put directly after 'genlmsghdr', thus we can just
           increment previous header pointer */
        struct nlattr *nla_resp = (struct nlattr *)(genlh_resp + 1);
        nla_resp->nla_len = response->vr_message_len;
        nla_resp->nla_type = NL_ATTR_VR_MESSAGE_PROTOCOL;

        PKSYNC_RESPONSE ks_resp = KsyncResponseCreate();
        if (ks_resp != NULL) {
            ks_resp->message_len = data_len;
            RtlCopyMemory(ks_resp->buffer, data, ks_resp->message_len);
            KsyncAppendResponse(ctx, ks_resp);
        } else {
            DbgPrint("%s: ksync_response allocation failed\n", __func__);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        response->vr_message_buf = NULL;
        vr_message_free(response);
    }

    if (multi_flag) {
        PKSYNC_RESPONSE ks_resp = KsyncResponseCreate();
        if (ks_resp == NULL) {
            DbgPrint("%s: ksync_response allocation failed\n", __func__);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        struct nlmsghdr *nlh_done = (struct nlmsghdr *)ks_resp->buffer;
        nlh_done->nlmsg_len = NLMSG_HDRLEN;
        nlh_done->nlmsg_type = NLMSG_DONE;
        nlh_done->nlmsg_flags = 0;
        nlh_done->nlmsg_seq = nlh->nlmsg_seq;
        nlh_done->nlmsg_pid = 0;

        ks_resp->message_len = NLMSG_HDRLEN;

        KsyncAppendResponse(ctx, ks_resp);
    }

    return STATUS_SUCCESS;
}

static VOID
KsyncCopyUserBufferToContext(PKSYNC_DEVICE_CONTEXT ctx,
                             ULONG bytesNeeded,
                             PCHAR *userBuffer,
                             ULONG *userBufferSize,
                             ULONG *writtenBytes)
{
    size_t bytesToWrite = *userBufferSize < bytesNeeded ? *userBufferSize : bytesNeeded;
    RtlCopyMemory(&ctx->WriteBuffer[ctx->WrittenBytes], *userBuffer, bytesToWrite);
    ctx->WrittenBytes += bytesToWrite;
    *writtenBytes += bytesToWrite;
    *userBufferSize -= bytesToWrite;
    *userBuffer += bytesToWrite;
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

    ULONG writtenBytes = 0;
    while (userBufferSize > 0) {
        if (ctx->WrittenBytes < sizeof(struct nlmsghdr)) {
            size_t bytesNeeded = sizeof(struct nlmsghdr) - ctx->WrittenBytes;
            KsyncCopyUserBufferToContext(ctx, bytesNeeded, &userBuffer, &userBufferSize, &writtenBytes);
        } else {
            struct nlmsghdr *nlh = (struct nlmsghdr *)ctx->WriteBuffer;
            if (nlh->nlmsg_len > ctx->WriteBufferSize) {
                KsyncContextResetWriteBuffer(ctx);
                return KSyncCompleteIrp(Irp, STATUS_UNSUCCESSFUL, 0);
            }

            size_t bytesNeeded = nlh->nlmsg_len - ctx->WrittenBytes;
            KsyncCopyUserBufferToContext(ctx, bytesNeeded, &userBuffer, &userBufferSize, &writtenBytes);

            if (ctx->WrittenBytes == nlh->nlmsg_len) {
                NTSTATUS status = KsyncHandleWrite(ctx, ctx->WriteBuffer, ctx->WrittenBytes);
                KsyncContextResetWriteBuffer(ctx);
                if (NT_ERROR(status)) {
                    DbgPrint("%s: KsyncHandleWrite returned an error: %x\n", __func__, status);
                    return KSyncCompleteIrp(Irp, STATUS_UNSUCCESSFUL, writtenBytes);
                }
            }
            break;
        }
    }

    return KSyncCompleteIrp(Irp, STATUS_SUCCESS, writtenBytes);
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
