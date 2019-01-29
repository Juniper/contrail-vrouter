/*
 * test_ksync_write_buffer.c
 *
 * Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "vr_ksync_parse.h"
#include <netlink.h>

#define BUFFER_SIZE 128

PCHAR msg = "abcd";
ULONG msgLen = 0;
PKSYNC_DEVICE_CONTEXT ctx = NULL;
PCHAR userBufferRaw = NULL;

int Test_WinKsyncWriteBuffer_SetUp(void **state) {
    msg = "abcd";
    msgLen = strlen(msg);
    ctx = KSyncAllocContext();

    assert_non_null(ctx);

    userBufferRaw = (PCHAR) test_malloc(BUFFER_SIZE);
    memset(userBufferRaw, 0, BUFFER_SIZE);
    return 0;
}

int Test_WinKsyncWriteBuffer_TearDown(void **state) {
    test_free(ctx);
    ctx = NULL;
    test_free(userBufferRaw);
    userBufferRaw = NULL;
    return 0;
}

void Test_WinKsyncWriteBuffer_alloc_context(void **state) {
    assert_non_null(ctx);
}

void Test_WinKsyncWriteBuffer_context_reset_write_buffer(void **state) {
    strncpy(ctx->WriteBuffer, msg, msgLen);
    ctx->WrittenBytes = msgLen;

    KsyncContextResetWriteBuffer(ctx);

    assert_int_equal(ctx->WrittenBytes, 0);
    assert_true(strcmp(ctx->WriteBuffer, "") == 0);
}

void Test_WinKsyncWriteBuffer_copy_user_buffer_to_context(void **state) {
    assert_true(BUFFER_SIZE > msgLen);
    
    PCHAR userBuffer = userBufferRaw;
    strncpy(userBuffer, msg, msgLen);
    ULONG userBufferSize = strlen(userBuffer);

    ULONG bytesNeeded = userBufferSize - ctx->WrittenBytes;

    ULONG writtenBytes = 0;
    KsyncCopyUserBufferToContext(ctx, bytesNeeded, &userBuffer, 
                                 &userBufferSize, &writtenBytes);

    assert_int_equal(0, userBufferSize);
    assert_int_equal(ctx->WrittenBytes, writtenBytes);
    assert_true(strncmp(userBuffer - writtenBytes,
                        ctx->WriteBuffer, writtenBytes) == 0);
}

void Test_WinKsyncWriteBuffer_complete_irp_raw(void **state) {
    IRP_DOLL irp;
    irp.Status = STATUS_UNSUCCESSFUL;
    irp.Information = (ULONG_PTR) 0;
    assert_int_equal(KSyncCompleteIrpRaw(&irp, STATUS_SUCCESS, 0),
                                         STATUS_SUCCESS);
    assert_int_equal(irp.Status, STATUS_SUCCESS);
    assert_int_equal((ULONG_PTR) NULL, irp.Information);
}

static void createMessage(PCHAR userBuffer, ULONG *userBufferSize,
                          ULONG count, PIRP_DOLL irp) {
    assert_true(BUFFER_SIZE > (sizeof(struct nlmsghdr) + msgLen) * count);

    irp->Status = STATUS_UNSUCCESSFUL;
    irp->Information = (UINT) 0;
    
    *userBufferSize = 0;
    while (count > 0) {
        struct nlmsghdr *nlh = (struct nlmsghdr*) userBuffer;

        *userBufferSize += sizeof(struct nlmsghdr) + msgLen;

        nlh->nlmsg_len = msgLen;
        strncpy(userBuffer + sizeof(struct nlmsghdr), msg, msgLen);

        userBuffer += *userBufferSize;
        --count;
    }

}

void Test_WinKsyncWriteBuffer_parse_write(void **state) {
    IRP_DOLL irp;
    PCHAR userBuffer = userBufferRaw;
    ULONG userBufferSize = 0;

    ULONG bulk_msg_count = 1;
    createMessage(userBuffer, &userBufferSize, bulk_msg_count, &irp);

    NTSTATUS status = KsyncParseWrite(ctx, userBuffer, userBufferSize, &irp);

    assert_int_equal(status, STATUS_SUCCESS);
    assert_int_equal(irp.Status, STATUS_SUCCESS);
}

void Test_WinKsyncWriteBuffer_parse_write_2msgs(void **state) {
    IRP_DOLL irp;
    PCHAR userBuffer = userBufferRaw;
    ULONG userBufferSize = 0;

    ULONG bulk_msg_count = 2;
    createMessage(userBuffer, &userBufferSize, bulk_msg_count, &irp);

    NTSTATUS status = KsyncParseWrite(ctx, userBuffer, userBufferSize, &irp);

    assert_int_equal(status, STATUS_SUCCESS);
    assert_int_equal(irp.Status, STATUS_SUCCESS);
}

#define WinKsyncWriteBuffer_UnitTest_(p, f) \
        cmocka_unit_test_setup_teardown(p##f, p##SetUp, p##TearDown)
#define WinKsyncWriteBuffer_UnitTest(f) \
        WinKsyncWriteBuffer_UnitTest_(Test_WinKsyncWriteBuffer_, f)


int main(void) {
    const struct CMUnitTest tests[] = {
        WinKsyncWriteBuffer_UnitTest(alloc_context),
        WinKsyncWriteBuffer_UnitTest(context_reset_write_buffer),
        WinKsyncWriteBuffer_UnitTest(copy_user_buffer_to_context),
        WinKsyncWriteBuffer_UnitTest(complete_irp_raw),
        WinKsyncWriteBuffer_UnitTest(parse_write),
        WinKsyncWriteBuffer_UnitTest(parse_write_2msgs),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}