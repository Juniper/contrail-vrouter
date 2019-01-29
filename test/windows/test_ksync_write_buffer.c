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

static void createMessage(PCHAR userBuffer,
                          ULONG *userBufferSize,
                          ULONG max_buffer_size,
                          PCHAR *messages,
                          ULONG bulk_msg_count)
{
    *userBufferSize = 0;
    ULONG i = 0;
    for (i = 0; i < bulk_msg_count; ++i) {
        if (max_buffer_size - *userBufferSize < NHL_SIZE) {
            *userBufferSize = max_buffer_size;
            break; // buffer's been zeroed, suppose nlmsg_len is 0
        }

        struct nlmsghdr *nlh = (struct nlmsghdr*) userBuffer;
        *userBufferSize += NHL_SIZE;
        userBuffer += NHL_SIZE;

        ULONG msgLen = strlen(messages[i]);
        nlh->nlmsg_len = msgLen + NHL_SIZE;
        ULONG incrSize = (msgLen > max_buffer_size - *userBufferSize )
                         ? max_buffer_size - *userBufferSize
                         : msgLen;

        strncpy(userBuffer, (PCHAR) messages[i], incrSize);

        *userBufferSize += incrSize;
        userBuffer += incrSize;
        if (incrSize < msgLen) {
            break;
        }
    }
}

void Test_WinKsyncWriteBuffer_create_message_test(void **state) {
    CHAR userBuffer[BUFFER_SIZE];
    ULONG userBufferSize = 0;
    PCHAR messages[] = { "abcd" };
    
    createMessage(&userBuffer[0], &userBufferSize, BUFFER_SIZE, messages, 1);

    CHAR userBufferCorrect[4 + NHL_SIZE];
    memset(userBufferCorrect, 0, 4 + NHL_SIZE);

    struct nlmsghdr *nlh = (struct nlmsghdr *) userBufferCorrect;
    nlh->nlmsg_len = 4 + NHL_SIZE;
    strncpy(userBufferCorrect + NHL_SIZE, messages[0], 4);

    assert_true(strncmp(userBufferCorrect, userBuffer,4 + NHL_SIZE) == 0);
}

void Test_WinKsyncWriteBuffer_create_message_test_2msgs(void **state) {
    CHAR userBuffer[BUFFER_SIZE];
    ULONG userBufferSize = 0;
    PCHAR messages[] = { "abcd", "message2" };
    
    createMessage(&userBuffer[0], &userBufferSize, BUFFER_SIZE, messages, 2);

    CHAR userBufferCorrect[BUFFER_SIZE];
    memset(userBufferCorrect, 0, BUFFER_SIZE);

    struct nlmsghdr *nlh = (struct nlmsghdr *) userBufferCorrect;
    nlh->nlmsg_len = 4 + NHL_SIZE;
    strncpy(&userBufferCorrect[0] + NHL_SIZE, messages[0], 4);

    nlh = (struct nlmsghdr *) &userBufferCorrect[4 + NHL_SIZE];
    nlh->nlmsg_len = 8 + NHL_SIZE;
    strncpy(&userBufferCorrect[4 + 2 * NHL_SIZE],
            messages[1], 8);

    assert_true(strncmp(userBufferCorrect, userBuffer,
                        4 + 8 + 2 * NHL_SIZE) == 0);
}

void Test_WinKsyncWriteBuffer_create_message_test_overhead(void **state) {
    CHAR userBuffer[BUFFER_SMALL];
    ULONG userBufferSize = 0;
    PCHAR messages[] = { "abcde" };
    
    createMessage(&userBuffer[0], &userBufferSize, BUFFER_SMALL, messages, 1);

    CHAR userBufferCorrect[BUFFER_SMALL];
    memset(userBufferCorrect, 0, BUFFER_SMALL);

    struct nlmsghdr *nlh = (struct nlmsghdr *) userBufferCorrect;
    nlh->nlmsg_len = strlen(messages[0]) + NHL_SIZE;
    strncpy(&userBufferCorrect[NHL_SIZE], messages[0],
            BUFFER_SMALL - NHL_SIZE);

    assert_int_equal(userBufferSize, BUFFER_SMALL);
    assert_true(strncmp(&userBufferCorrect[0],
                        &userBuffer[0], BUFFER_SMALL) == 0);
}

void Test_WinKsyncWriteBuffer_copy_user_buffer_to_context(void **state) {
    CHAR userBufferRaw[BUFFER_SIZE];
    PCHAR messages[] = { "abcd" };

    PCHAR userBuffer = &userBufferRaw[0];
    ULONG userBufferSize = 0;
    
    createMessage(&userBuffer[0], &userBufferSize, BUFFER_SIZE, messages, 1);

    ULONG bytesNeeded = NHL_SIZE - ctx->WrittenBytes;

    ULONG writtenBytes = 0;
    KsyncCopyUserBufferToContext(ctx, bytesNeeded, &userBuffer, 
                                 &userBufferSize, &writtenBytes);
    assert_true(strncmp(ctx->WriteBuffer, userBufferRaw,
                        NHL_SIZE) == 0);

    struct nlmsghdr *nlh = (struct nlmsghdr *) ctx->WriteBuffer;

    bytesNeeded = nlh->nlmsg_len - ctx->WrittenBytes;
    KsyncCopyUserBufferToContext(ctx, bytesNeeded, &userBuffer, 
                                 &userBufferSize, &writtenBytes);

    assert_int_equal(0, userBufferSize);
    assert_int_equal(NHL_SIZE + 4, writtenBytes);
    assert_int_equal(ctx->WrittenBytes, writtenBytes);
    assert_true(strncmp(userBufferRaw, ctx->WriteBuffer, writtenBytes) == 0);
}

void Test_WinKsyncWriteBuffer_context_reset_write_buffer(void **state) {
    CHAR userBufferRaw[BUFFER_SIZE];
    PCHAR messages[] = { "abcd" };

    PCHAR userBuffer = &userBufferRaw[0];
    ULONG userBufferSize = 0;
    
    ULONG writtenBytes = 0;
    createMessage(userBuffer, &userBufferSize, BUFFER_SIZE, messages, 1);
    KsyncCopyUserBufferToContext(ctx, NHL_SIZE + 4, &userBuffer,
                                 &userBufferSize, &writtenBytes);

    KsyncContextResetWriteBuffer(ctx);

    assert_int_equal(ctx->WrittenBytes, 0);
    assert_true(strcmp(ctx->WriteBuffer, "") == 0);
}

void Test_WinKsyncWriteBuffer_parse_write(void **state) {
    CHAR userBufferRaw[BUFFER_SIZE];
    PCHAR messages[] = { "abcd" };

    PCHAR userBuffer = &userBufferRaw[0];
    ULONG userBufferSize = 0;
    
    createMessage(userBuffer, &userBufferSize, BUFFER_SIZE, messages, 1);

    PairStatusInformation psi =
        KsyncParseAndHandleWrite(ctx, userBuffer, userBufferSize);

    assert_int_equal(GetHandleWriteCounter(), 1);
    assert_int_equal(0, ctx->WrittenBytes);
    assert_int_equal(psi.Status, STATUS_SUCCESS);
}

void Test_WinKsyncWriteBuffer_parse_write_2msgs(void **state) {
    CHAR userBufferRaw[BUFFER_SIZE];
    PCHAR messages[] = { "abcd", "xxxxxxx" };

    PCHAR userBuffer = &userBufferRaw[0];
    ULONG userBufferSize = 0;
    
    createMessage(userBuffer, &userBufferSize, BUFFER_SIZE, messages, 2);

    PairStatusInformation psi =
        KsyncParseAndHandleWrite(ctx, userBuffer, userBufferSize);

    assert_int_equal(GetHandleWriteCounter(), 2);
    assert_int_equal(psi.Information, NHL_SIZE * 2 + strlen("abcd" "xxxxxxx"));
    assert_int_equal(psi.Status, STATUS_SUCCESS);
}

void Test_WinKsyncWriteBuffer_parse_write_overhead(void **state) {
    CHAR userBufferRaw[BUFFER_SIZE];
    PCHAR messages[] = { "aaa" };

    PCHAR userBuffer = &userBufferRaw[0];
    ULONG userBufferSize = 0;
    
    createMessage(userBuffer, &userBufferSize, BUFFER_SIZE, messages, 1);
    struct nlmsghdr *nlh = (struct nlmsghdr *) userBuffer;

    // imitate message length
    nlh->nlmsg_len = ctx->WriteBufferSize + 2;
    userBufferSize = nlh->nlmsg_len + NHL_SIZE;

    PairStatusInformation psi =
        KsyncParseAndHandleWrite(ctx, userBuffer, userBufferSize);

    assert_int_equal(0, ctx->WrittenBytes);
    assert_int_equal(GetHandleWriteCounter(), 0);
    assert_int_equal(psi.Information, ctx->WrittenBytes);
    assert_int_equal(psi.Status, STATUS_UNSUCCESSFUL);
}

#define WinKsyncWriteBuffer_UnitTest_(p, f) \
        cmocka_unit_test_setup_teardown(p##f, p##SetUp, p##TearDown)
#define WinKsyncWriteBuffer_UnitTest(f) \
        WinKsyncWriteBuffer_UnitTest_(Test_WinKsyncWriteBuffer_, f)

int main(void) {
    const struct CMUnitTest tests[] = {
        WinKsyncWriteBuffer_UnitTest(create_message_test),
        WinKsyncWriteBuffer_UnitTest(create_message_test_2msgs),
        WinKsyncWriteBuffer_UnitTest(create_message_test_overhead),
        WinKsyncWriteBuffer_UnitTest(copy_user_buffer_to_context),
        WinKsyncWriteBuffer_UnitTest(context_reset_write_buffer),
        WinKsyncWriteBuffer_UnitTest(parse_write),
        WinKsyncWriteBuffer_UnitTest(parse_write_2msgs),
        WinKsyncWriteBuffer_UnitTest(parse_write_overhead),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}