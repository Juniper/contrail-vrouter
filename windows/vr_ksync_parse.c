/* 
 * vr_ksync_parse.c
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_ksync_parse.h"
#include "win_memory.h"
#include "win_dbg_print.h"
#include <windows_types.h>
#include <netlink.h>

ULONG KsyncAllocationTag = 'NYSK';

PKSYNC_DEVICE_CONTEXT
KSyncAllocContext()
{
    PKSYNC_DEVICE_CONTEXT ctx = WinRawAllocateWithTag(sizeof(*ctx),
                                                      KsyncAllocationTag);
    if (ctx == NULL)
        return NULL;

    ctx->WrittenBytes = 0;
    ctx->WriteBufferSize = sizeof(ctx->WriteBuffer);
    WinRawZeroMemory(ctx->WriteBuffer, ctx->WriteBufferSize);

    ctx->responses = NULL;

    return ctx;
}

VOID
KsyncCopyUserBufferToContext(PKSYNC_DEVICE_CONTEXT ctx,
                             ULONG bytesNeeded,
                             PCHAR *userBuffer,
                             ULONG *userBufferSize,
                             ULONG *writtenBytes)
{
    size_t bytesToWrite = *userBufferSize < bytesNeeded ? *userBufferSize
                                                        : bytesNeeded;
    WinRawMemCpy(&(ctx->WriteBuffer[ctx->WrittenBytes]),
                 *userBuffer, bytesToWrite);
    ctx->WrittenBytes += bytesToWrite;
    *writtenBytes += bytesToWrite;
    *userBufferSize -= bytesToWrite;
    *userBuffer += bytesToWrite;
}

VOID
KsyncContextResetWriteBuffer(PKSYNC_DEVICE_CONTEXT ctx)
{
    ctx->WrittenBytes = 0;
    WinRawZeroMemory(ctx->WriteBuffer, ctx->WriteBufferSize);
}

NTSTATUS
KsyncParseWrite(PKSYNC_DEVICE_CONTEXT ctx,
                PCHAR userBuffer,
                ULONG userBufferSize,
                PIRP_DOLL IrpRaw)
{
    ULONG writtenBytes = 0;
    while (userBufferSize > 0) {
        if (ctx->WrittenBytes < sizeof(struct nlmsghdr)) {
            size_t bytesNeeded = sizeof(struct nlmsghdr) - ctx->WrittenBytes;
            KsyncCopyUserBufferToContext(ctx, bytesNeeded, &userBuffer,
                                         &userBufferSize, &writtenBytes);
        } else {
            struct nlmsghdr *nlh = (struct nlmsghdr *)ctx->WriteBuffer;
            if (nlh->nlmsg_len > ctx->WriteBufferSize) {
                KsyncContextResetWriteBuffer(ctx);
                return KSyncCompleteIrpRaw(IrpRaw, STATUS_UNSUCCESSFUL, 0);
            }

            size_t bytesNeeded = nlh->nlmsg_len - ctx->WrittenBytes;
            KsyncCopyUserBufferToContext(ctx, bytesNeeded, &userBuffer,
                                         &userBufferSize, &writtenBytes);

            if (ctx->WrittenBytes == nlh->nlmsg_len) {
                NTSTATUS status = KsyncHandleWrite(ctx, ctx->WriteBuffer,
                                                   ctx->WrittenBytes);
                KsyncContextResetWriteBuffer(ctx);
                if (NT_ERROR(status)) {
                    WinDbgPrint("%s: KsyncHandleWrite "
                                "returned an error: %x\n",
                                __func__, status);
                    return KSyncCompleteIrpRaw(IrpRaw, STATUS_UNSUCCESSFUL, 0);
                }
            }
            break;
        }
    }

    return KSyncCompleteIrpRaw(IrpRaw, STATUS_SUCCESS, 0);
}