/*
 * vr_ksync_user.c
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_ksync_user.h"
#include "vr_ksync_kernel.h"
#include <netlink.h>

RESULT_STATUS_INFO
KsyncParseAndHandleWrite(PKSYNC_DEVICE_CONTEXT ctx,
                         PCHAR userBuffer,
                         ULONG userBufferSize)
{
    RESULT_STATUS_INFO result = { STATUS_UNSUCCESSFUL, 0 };
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
                return result;
            }

            size_t bytesNeeded = nlh->nlmsg_len - ctx->WrittenBytes;
            KsyncCopyUserBufferToContext(ctx, bytesNeeded, &userBuffer,
                                         &userBufferSize, &writtenBytes);

            if (ctx->WrittenBytes == nlh->nlmsg_len) {
                NTSTATUS status = KsyncHandleWrite(ctx, ctx->WriteBuffer,
                                                   ctx->WrittenBytes);
                KsyncContextResetWriteBuffer(ctx);
                if (NT_ERROR(status)) {
                    result.Information = writtenBytes;
                    return result;
                }
            }
        }
    }
    result.Status = STATUS_SUCCESS;
    result.Information = writtenBytes;
    return result;
}