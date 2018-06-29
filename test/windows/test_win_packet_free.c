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
static VOID (*Saved_WinPacketRawFreeCreated)(PWIN_PACKET Packet);

static bool WasWinPacketRawCompleteCalled;
static PWIN_PACKET WinPacketRawCompleteTarget;

static bool WasWinPacketRawFreeCreatedCalled;

static VOID
Fake_WinPacketRawComplete(PWIN_PACKET Packet)
{
    WasWinPacketRawCompleteCalled = WinPacketRawCompleteTarget == Packet;
    Fake_WinPacketFree(Packet);
}

static VOID
Fake_WinPacketRawFreeCreated(PWIN_PACKET Packet)
{
    WasWinPacketRawFreeCreatedCalled = true;
    Fake_WinPacketFree(Packet);
}

int
Test_WinPacketFree_SetUp(void **state)
{
    WasWinPacketRawCompleteCalled = FALSE;
    WasWinPacketRawFreeCreatedCalled = FALSE;

    Saved_WinPacketRawComplete = WinPacketRawComplete;
    WinPacketRawComplete = Fake_WinPacketRawComplete;

    Saved_WinPacketRawFreeCreated = WinPacketRawFreeCreated;
    WinPacketRawFreeCreated = Fake_WinPacketRawFreeCreated;

    return 0;
}

int
Test_WinPacketFree_TearDown(void **state)
{
    WinPacketRawComplete = Saved_WinPacketRawComplete;
    WinPacketRawFreeCreated = Saved_WinPacketRawFreeCreated;

    return 0;
}

void
Test_WinPacketFree_NotOursWithoutChildrenIsCompleted(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocate();
    Fake_WinPacketSetIsOwned(packet, FALSE);
    WinPacketRawCompleteTarget = packet;

    WinPacketFree(packet);
    assert_true(WasWinPacketRawCompleteCalled);
    assert_false(WasWinPacketRawFreeCreatedCalled);
}

void
Test_WinPacketFree_NotOursWithChildrenAssertsOnChildCount(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocate();
    WinPacketRawIncrementChildCountOf(packet);
    Fake_WinPacketSetIsOwned(packet, FALSE);
    WinPacketRawCompleteTarget = packet;

    expect_assert_failure(WinPacketFree(packet));
    assert_false(WasWinPacketRawCompleteCalled);
    assert_false(WasWinPacketRawFreeCreatedCalled);

    Fake_WinPacketFree(packet);
}

void
Test_WinPacketFree_OursNotClonedWithoutChildrenIsFreed(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocate();
    Fake_WinPacketSetIsOwned(packet, TRUE);
    WinPacketRawCompleteTarget = packet;

    WinPacketFree(packet);
    assert_false(WasWinPacketRawCompleteCalled);
    assert_true(WasWinPacketRawFreeCreatedCalled);
}

void
Test_WinPacketFree_OursNotClonedWithChildrenAssertsOnChildCount(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocate();
    WinPacketRawIncrementChildCountOf(packet);
    Fake_WinPacketSetIsOwned(packet, TRUE);
    WinPacketRawCompleteTarget = packet;

    expect_assert_failure(WinPacketFree(packet));
    assert_false(WasWinPacketRawCompleteCalled);
    assert_false(WasWinPacketRawFreeCreatedCalled);

    Fake_WinPacketFree(packet);
}

#define WinPacketFree_UnitTest_(p, f) cmocka_unit_test_setup_teardown(p##f, p##SetUp, p##TearDown)
#define WinPacketFree_UnitTest(f) WinPacketFree_UnitTest_(Test_WinPacketFree_, f)

int main(void) {
    const struct CMUnitTest tests[] = {
        WinPacketFree_UnitTest(NotOursWithoutChildrenIsCompleted),
        WinPacketFree_UnitTest(NotOursWithChildrenAssertsOnChildCount),
        WinPacketFree_UnitTest(OursNotClonedWithoutChildrenIsFreed),
        WinPacketFree_UnitTest(OursNotClonedWithChildrenAssertsOnChildCount),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
