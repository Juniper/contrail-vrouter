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

#include "vr_ksync_user.h"
#include <netlink.h>

PKSYNC_DEVICE_CONTEXT ctx = NULL;
#define NHL_SIZE sizeof(struct nlmsghdr)
#define BUFFER_SMALL (NHL_SIZE + 4)
#define BUFFER_SIZE 128

int Test_WinKsyncWriteBuffer_SetUp(void **state) {
    ResetHandleWriteCounter();
    ctx = KsyncAllocContext();
    return 0;
}

int Test_WinKsyncWriteBuffer_TearDown(void **state) {
    KsyncDeleteContext(ctx);
    return 0;
}

// Add header and message to the end of the buffer.
static void createMessage(PCHAR userBuffer,
                          ULONG *userBufferSize,
                          ULONG max_buffer_size,
                          PCHAR message)
{
    if (max_buffer_size - *userBufferSize < NHL_SIZE) {
        *userBufferSize = max_buffer_size;
        return; // buffer's been zeroed, suppose nlmsg_len is 0
    }

    struct nlmsghdr *nlh = (struct nlmsghdr*) &userBuffer[*userBufferSize];
    *userBufferSize += NHL_SIZE;

    ULONG msgLen = strlen(message);
    nlh->nlmsg_len = msgLen + NHL_SIZE;
    ULONG incrSize = (msgLen > max_buffer_size - *userBufferSize )
                      ? max_buffer_size - *userBufferSize
                      : msgLen;

    strncpy(&userBuffer[*userBufferSize], message, incrSize);

    *userBufferSize += incrSize;
}

void Test_WinKsyncWriteBuffer_create_message_test(void **state) {
    CHAR userBuffer[BUFFER_SIZE] = { 0 };
    ULONG userBufferSize = 0;
    PCHAR message = "abcd";
    createMessage(userBuffer, &userBufferSize, BUFFER_SIZE, message);

    CHAR userBufferCorrect[4 + NHL_SIZE] = { 0 };

    struct nlmsghdr *nlh = (struct nlmsghdr *) userBufferCorrect;
    nlh->nlmsg_len = 4 + NHL_SIZE;
    strncpy(userBufferCorrect + NHL_SIZE, message, 4);

    assert_true(strncmp(userBufferCorrect, userBuffer, 4 + NHL_SIZE) == 0);
}

void Test_WinKsyncWriteBuffer_create_message_test_overhead(void **state) {
    CHAR userBuffer[NHL_SIZE + 4] = { 0 };
    ULONG smallBuffer = NHL_SIZE + 4;
    ULONG userBufferSize = 0;
    PCHAR message = "abcde";
    createMessage(userBuffer, &userBufferSize, smallBuffer, message);

    CHAR userBufferCorrect[NHL_SIZE + 4] = { 0 };

    struct nlmsghdr *nlh = (struct nlmsghdr *) userBufferCorrect;
    nlh->nlmsg_len = strlen(message) + NHL_SIZE;
    strncpy(&userBufferCorrect[NHL_SIZE], message, smallBuffer - NHL_SIZE);

    assert_int_equal(userBufferSize, smallBuffer);
    assert_true(strncmp(&userBufferCorrect[0],
                        &userBuffer[0], smallBuffer) == 0);
}

void Test_WinKsyncWriteBuffer_copy_user_buffer_to_context(void **state) {
    PCHAR message = "abcd";
    ULONG bytesNeeded = strlen(message);
    PCHAR userBuffer = message;
    ULONG userBufferLen = bytesNeeded;
    ULONG writtenBytes = 0;

    KsyncCopyUserBufferToContext(ctx, bytesNeeded, &userBuffer,
                                 &userBufferLen, &writtenBytes);

    assert_int_equal(0, userBufferLen);
    assert_int_equal(bytesNeeded, writtenBytes);
    assert_int_equal(ctx->WrittenBytes, writtenBytes);
    assert_true(strncmp(message, ctx->WriteBuffer, writtenBytes) == 0);
    assert_true(strcmp(userBuffer, "") == 0);
}

void Test_WinKsyncWriteBuffer_context_reset_write_buffer(void **state) {
    PCHAR message = "abcd";
    ULONG bytesNeeded = strlen(message);
    ULONG messageLen = strlen(message);
    ULONG writtenBytes = 0;

    KsyncCopyUserBufferToContext(ctx, bytesNeeded, &message,
                                 &messageLen, &writtenBytes);

    KsyncContextResetWriteBuffer(ctx);

    assert_int_equal(ctx->WrittenBytes, 0);
    assert_true(strcmp(ctx->WriteBuffer, "") == 0);
}

void Test_WinKsyncWriteBuffer_parse_write(void **state) {
    CHAR userBufferRaw[BUFFER_SIZE] = { 0 };
    PCHAR message = "abcd";

    PCHAR userBuffer = &userBufferRaw[0];
    ULONG userBufferSize = 0;

    createMessage(userBuffer, &userBufferSize, BUFFER_SIZE, message);

    RESULT_STATUS_INFO result =
        KsyncParseAndHandleWrite(ctx, userBuffer, userBufferSize);

    assert_int_equal(GetHandleWriteCounter(), 1);
    assert_int_equal(0, ctx->WrittenBytes);
    assert_int_equal(result.Status, STATUS_SUCCESS);
    assert_int_equal(result.Information, userBufferSize);
}

void Test_WinKsyncWriteBuffer_parse_write_2msgs(void **state) {
    CHAR userBufferRaw[BUFFER_SIZE] = { 0 };
    PCHAR messages[] = { "abcd", "xxxxxxx" };

    PCHAR userBuffer = &userBufferRaw[0];
    ULONG userBufferSize = 0;

    createMessage(userBufferRaw, &userBufferSize, BUFFER_SIZE, messages[0]);
    createMessage(userBufferRaw, &userBufferSize, BUFFER_SIZE, messages[1]);

    RESULT_STATUS_INFO result =
        KsyncParseAndHandleWrite(ctx, userBuffer, userBufferSize);

    assert_int_equal(GetHandleWriteCounter(), 2);
    assert_int_equal(0, ctx->WrittenBytes);
    assert_int_equal(result.Information, userBufferSize);
    assert_int_equal(result.Status, STATUS_SUCCESS);
    assert_true(strcmp(ctx->WriteBuffer, "") == 0);
}

void Test_WinKsyncWriteBuffer_parse_write_overhead(void **state) {
    CHAR userBuffer[BUFFER_SIZE] = { 0 };
    ULONG userBufferSize = 0;
    PCHAR message = "aaa";

    createMessage(userBuffer, &userBufferSize, BUFFER_SIZE, message);
    struct nlmsghdr *nlh = (struct nlmsghdr *) userBuffer;

    // imitate message length
    nlh->nlmsg_len = ctx->WriteBufferSize + 2;

    RESULT_STATUS_INFO result =
        KsyncParseAndHandleWrite(ctx, userBuffer, userBufferSize);

    assert_int_equal(0, ctx->WrittenBytes);
    assert_int_equal(GetHandleWriteCounter(), 0);
    assert_int_equal(result.Information, 0);
    assert_int_equal(result.Status, STATUS_UNSUCCESSFUL);
}

#define WinKsyncWriteBuffer_UnitTest_(p, f) \
        cmocka_unit_test_setup_teardown(p##f, p##SetUp, p##TearDown)
#define WinKsyncWriteBuffer_UnitTest(f) \
        WinKsyncWriteBuffer_UnitTest_(Test_WinKsyncWriteBuffer_, f)

int main(void) {
    const struct CMUnitTest tests[] = {
        WinKsyncWriteBuffer_UnitTest(create_message_test),
        WinKsyncWriteBuffer_UnitTest(create_message_test_overhead),
        WinKsyncWriteBuffer_UnitTest(copy_user_buffer_to_context),
        WinKsyncWriteBuffer_UnitTest(context_reset_write_buffer),
        WinKsyncWriteBuffer_UnitTest(parse_write),
        WinKsyncWriteBuffer_UnitTest(parse_write_2msgs),
        WinKsyncWriteBuffer_UnitTest(parse_write_overhead),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}