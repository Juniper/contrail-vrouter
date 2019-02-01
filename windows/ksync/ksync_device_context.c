/*
 * ksync_device_context.c
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */
#include "ksync_device_context.h"
#include "ksync_allocation.h"
#include "win_memory.h"

PKSYNC_DEVICE_CONTEXT
KsyncAllocContext()
{
    PKSYNC_DEVICE_CONTEXT ctx = KsyncAllocateMemory(sizeof(*ctx));
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

VOID
KsyncAppendResponse(PKSYNC_DEVICE_CONTEXT ctx, PKSYNC_RESPONSE resp)
{
    PKSYNC_RESPONSE  elem;
    PKSYNC_RESPONSE *iter = &ctx->responses;

    while (*iter != NULL) {
        elem = *iter;
        iter = &(elem->next);
    }

    *iter = resp;
}

VOID
KsyncPrependResponse(PKSYNC_DEVICE_CONTEXT ctx, PKSYNC_RESPONSE resp)
{
    resp->next = ctx->responses;
    ctx->responses = resp;
}

PKSYNC_RESPONSE
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

VOID
KsyncDeleteContext(PKSYNC_DEVICE_CONTEXT ctx)
{
    while (ctx->responses != NULL) {
        PKSYNC_RESPONSE prev = ctx->responses;
        ctx->responses = ctx->responses->next;
        KsyncFreeMemory(prev);
    }
    KsyncFreeMemory(ctx);
}
