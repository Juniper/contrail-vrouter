/*
 * test_win_packet_clone.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <setjmp.h>
#include <cmocka.h>

#include "win_packet.h"
#include "fake_win_packet.h"

static PWIN_PACKET (*Saved_WinPacketRawAllocateClone)(PWIN_PACKET Packet);

static PWIN_PACKET
Fake_WinPacketRawAllocateClone_ReturnsNull(PWIN_PACKET Packet)
{
    return NULL;
}

static PWIN_PACKET
Fake_WinPacketRawAllocateClone_ReturnsNewPacket(PWIN_PACKET Packet)
{
    return Fake_WinPacketAllocate();
}

int
Test_WinPacketClone_SetUp(void **state)
{
    Saved_WinPacketRawAllocateClone = WinPacketRawAllocateClone;
    return 0;
}

int
Test_WinPacketClone_TearDown(void **state)
{
    WinPacketRawAllocateClone = Saved_WinPacketRawAllocateClone;
    return 0;
}

void
Test_WinPacketClone_ReturnsNullWhenCloneFails(void **state)
{
    WinPacketRawAllocateClone = Fake_WinPacketRawAllocateClone_ReturnsNull;

    PWIN_PACKET packet = Fake_WinPacketAllocate();
    PWIN_PACKET cloned = WinPacketClone(packet);

    assert_null(cloned);
    assert_int_equal(WinPacketRawGetChildCountOf(packet), 0);

    Fake_WinPacketFree(packet);
}

void
Test_WinPacketClone_ReturnsPacketWhenCloneSucceeds(void **state)
{
    WinPacketRawAllocateClone = Fake_WinPacketRawAllocateClone_ReturnsNewPacket;

    PWIN_PACKET packet = Fake_WinPacketAllocate();
    PWIN_PACKET cloned = WinPacketClone(packet);

    assert_non_null(cloned);
    assert_ptr_equal(WinPacketRawGetParentOf(cloned), packet);
    assert_int_equal(WinPacketRawGetChildCountOf(packet), 1);

    Fake_WinPacketFree(cloned);
    Fake_WinPacketFree(packet);
}

void
Test_WinPacketClone_RefCountIsValidAfterMultipleClones(void **state)
{
    WinPacketRawAllocateClone = Fake_WinPacketRawAllocateClone_ReturnsNewPacket;

    PWIN_PACKET packet = Fake_WinPacketAllocate();

    PWIN_PACKET cloned1 = WinPacketClone(packet);
    PWIN_PACKET cloned2 = WinPacketClone(packet);
    PWIN_PACKET cloned3 = WinPacketClone(packet);

    assert_ptr_equal(WinPacketRawGetParentOf(cloned1), packet);
    assert_ptr_equal(WinPacketRawGetParentOf(cloned2), packet);
    assert_ptr_equal(WinPacketRawGetParentOf(cloned3), packet);

    assert_int_equal(WinPacketRawGetChildCountOf(packet), 3);
    assert_int_equal(WinPacketRawGetChildCountOf(cloned1), 0);
    assert_int_equal(WinPacketRawGetChildCountOf(cloned2), 0);
    assert_int_equal(WinPacketRawGetChildCountOf(cloned3), 0);

    Fake_WinPacketFree(cloned1);
    Fake_WinPacketFree(cloned2);
    Fake_WinPacketFree(cloned3);
    Fake_WinPacketFree(packet);
}

void
Test_WinPacketClone_RefCountIsValidAfterCloneOfClone(void **state)
{
    WinPacketRawAllocateClone = Fake_WinPacketRawAllocateClone_ReturnsNewPacket;

    PWIN_PACKET packet = Fake_WinPacketAllocate();

    PWIN_PACKET cloned1 = WinPacketClone(packet);
    PWIN_PACKET cloned2 = WinPacketClone(cloned1);

    assert_ptr_equal(WinPacketRawGetParentOf(cloned1), packet);
    assert_ptr_equal(WinPacketRawGetParentOf(cloned2), cloned1);

    assert_int_equal(WinPacketRawGetChildCountOf(packet), 1);
    assert_int_equal(WinPacketRawGetChildCountOf(cloned1), 1);
    assert_int_equal(WinPacketRawGetChildCountOf(cloned2), 0);

    Fake_WinPacketFree(cloned2);
    Fake_WinPacketFree(cloned1);
    Fake_WinPacketFree(packet);
}

#define WinPacketClone_UnitTest_(p, f) cmocka_unit_test_setup_teardown(p##f, p##SetUp, p##TearDown)
#define WinPacketClone_UnitTest(f) WinPacketClone_UnitTest_(Test_WinPacketClone_, f)

int main(void) {
    const struct CMUnitTest tests[] = {
        WinPacketClone_UnitTest(ReturnsNullWhenCloneFails),
        WinPacketClone_UnitTest(ReturnsPacketWhenCloneSucceeds),
        WinPacketClone_UnitTest(RefCountIsValidAfterMultipleClones),
        WinPacketClone_UnitTest(RefCountIsValidAfterCloneOfClone),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
