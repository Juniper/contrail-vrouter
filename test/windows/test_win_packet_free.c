/*
 * test_win_packet_free.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <setjmp.h>
#include <cmocka.h>

#include "win_packet.h"
#include "fake_win_packet.h"

static VOID (*Saved_WinPacketRawComplete)(PWIN_PACKET Packet);

static bool WasWinPacketRawCompleteCalled;
static PWIN_PACKET WinPacketRawCompleteTarget;

static VOID
Fake_WinPacketRawComplete(PWIN_PACKET Packet)
{
    WasWinPacketRawCompleteCalled = WinPacketRawCompleteTarget == Packet;
    Fake_WinPacketFree(Packet);
}

void
Test_WinPacketFree_NotOursWithoutChildrenIsCompleted(void **state)
{
    Saved_WinPacketRawComplete = WinPacketRawComplete;
    WinPacketRawComplete = Fake_WinPacketRawComplete;

    PWIN_PACKET packet = Fake_WinPacketAllocate();
    Fake_WinPacketSetIsOwned(packet, FALSE);
    WasWinPacketRawCompleteCalled = FALSE;
    WinPacketRawCompleteTarget = packet;

    WinPacketFree(packet);
    assert_true(WasWinPacketRawCompleteCalled);

    WinPacketRawComplete = Saved_WinPacketRawComplete;
}

void
Test_WinPacketFree_NotOursWithChildrenAssertsOnChildCount(void **state)
{
    Saved_WinPacketRawComplete = WinPacketRawComplete;
    WinPacketRawComplete = Fake_WinPacketRawComplete;

    PWIN_PACKET packet = Fake_WinPacketAllocate();
    WinPacketRawIncrementChildCountOf(packet);
    Fake_WinPacketSetIsOwned(packet, FALSE);
    WasWinPacketRawCompleteCalled = FALSE;
    WinPacketRawCompleteTarget = packet;

    expect_assert_failure(WinPacketFree(packet));
    assert_false(WasWinPacketRawCompleteCalled);

    Fake_WinPacketFree(packet);

    WinPacketRawComplete = Saved_WinPacketRawComplete;
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(Test_WinPacketFree_NotOursWithoutChildrenIsCompleted),
        cmocka_unit_test(Test_WinPacketFree_NotOursWithChildrenAssertsOnChildCount),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
