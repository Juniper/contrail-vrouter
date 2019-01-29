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

#define BUFFER_SIZE 4096

void Test_if_works(void **state) {
    assert_true(true);
}

void Test_Ksync_alloc_context(void **state) {
    PKSYNC_DEVICE_CONTEXT ctx = KSyncAllocContext();
    assert_non_null(ctx);
    test_free(ctx);
}

void Test_Ksync_context_reset_write_buffer(void **state) {
    PKSYNC_DEVICE_CONTEXT ctx = KSyncAllocContext();
    strncpy(ctx->WriteBuffer, "abcd", strlen("abcd"));
    ctx->WrittenBytes = strlen("abcd");

    KsyncContextResetWriteBuffer(ctx);

    assert_int_equal(ctx->WrittenBytes, 0);
    assert_true(strcmp(ctx->WriteBuffer, "") == 0);
    test_free(ctx);
}

void Test_Ksync_copy_user_buffer_to_context(void **state) {
    PCHAR userBuffer = "abcd";
    ULONG userBufferSize = strlen(userBuffer);
    PKSYNC_DEVICE_CONTEXT ctx = KSyncAllocContext();
    ULONG bytesNeeded = userBufferSize - ctx->WrittenBytes;

    ULONG writtenBytes = 0;
    KsyncCopyUserBufferToContext(ctx, bytesNeeded, &userBuffer, 
                                 &userBufferSize, &writtenBytes);

    assert_int_equal(0, userBufferSize);
    assert_int_equal(ctx->WrittenBytes, writtenBytes);
    assert_true(strncmp(userBuffer - writtenBytes,
                        ctx->WriteBuffer, writtenBytes) == 0);
    test_free(ctx);
}

void Test_Ksync_complete_irp_raw(void **state) {
    IRP_DOLL irp;
    irp.Status = STATUS_UNSUCCESSFUL;
    irp.Information = (ULONG_PTR) 0;
    assert_int_equal(KSyncCompleteIrpRaw(&irp, STATUS_SUCCESS, 0), STATUS_SUCCESS);
    assert_int_equal(irp.Status, STATUS_SUCCESS);
    assert_int_equal((ULONG_PTR) NULL, irp.Information);
}

void Test_Ksync_parse_write(void **state) {
    PKSYNC_DEVICE_CONTEXT ctx = KSyncAllocContext();

    IRP_DOLL irp;
    irp.Status = STATUS_UNSUCCESSFUL;
    irp.Information = (UINT) 0;

    PCHAR msg = "abcd";
    ULONG msgLen = strlen("abcd");

    ULONG userBufferSize = sizeof(struct nlmsghdr) + msgLen;
    CHAR userBuffer[sizeof(struct nlmsghdr) + sizeof(msg)];
    memset(userBuffer, 0, userBufferSize);
    struct nlmsghdr *nlh = (struct nlmsghdr*) &userBuffer;
    nlh->nlmsg_len = userBufferSize - sizeof(struct nlmsghdr);

    strncpy(userBuffer + sizeof(struct nlmsghdr), msg, msgLen);

    NTSTATUS status = KsyncParseWrite(ctx, userBuffer, userBufferSize, &irp);
    assert_int_equal(status, STATUS_SUCCESS);
    assert_int_equal(irp.Status, STATUS_SUCCESS);
    test_free(ctx);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(Test_if_works),
        cmocka_unit_test(Test_Ksync_alloc_context),
        cmocka_unit_test(Test_Ksync_context_reset_write_buffer),
        cmocka_unit_test(Test_Ksync_copy_user_buffer_to_context),
        cmocka_unit_test(Test_Ksync_complete_irp_raw),
        cmocka_unit_test(Test_Ksync_parse_write),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}