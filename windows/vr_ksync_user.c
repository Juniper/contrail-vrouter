/* 
 * vr_ksync_user.c
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#include "vr_ksync_user.h"
#include "vr_ksync_kernel.h"
#include <netlink.h>

PairStatusInformation
KsyncParseAndHandleWrite(PKSYNC_DEVICE_CONTEXT ctx,
                         PCHAR userBuffer,
                         ULONG userBufferSize)
{
    PairStatusInformation psi = { STATUS_UNSUCCESSFUL, 0 };
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
                return psi;
            }

            size_t bytesNeeded = nlh->nlmsg_len - ctx->WrittenBytes;
            KsyncCopyUserBufferToContext(ctx, bytesNeeded, &userBuffer,
                                         &userBufferSize, &writtenBytes);

            if (ctx->WrittenBytes == nlh->nlmsg_len) {
                NTSTATUS status = KsyncHandleWrite(ctx, ctx->WriteBuffer,
                                                   ctx->WrittenBytes);
                KsyncContextResetWriteBuffer(ctx);
                if (NT_ERROR(status)) {
                    psi.Information = writtenBytes;
                    return psi;
                }
            }
        }
    }
    psi.Status = STATUS_SUCCESS;
    psi.Information = writtenBytes;
    return psi;
}