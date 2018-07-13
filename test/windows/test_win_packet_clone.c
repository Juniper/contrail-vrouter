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
#include "win_packet_impl.h"
#include "fake_win_packet.h"

static PWIN_PACKET_RAW (*Saved_WinPacketRawAllocateClone)(PWIN_PACKET_RAW Packet);

static PWIN_PACKET_RAW
Fake_WinPacketRawAllocateClone_ReturnsNull(PWIN_PACKET_RAW Packet)
{
    return NULL;
}

static PWIN_PACKET_RAW
Fake_WinPacketRawAllocateClone_ReturnsNewPacket(PWIN_PACKET_RAW Packet)
{
    return WinPacketToRawPacket(Fake_WinPacketAllocateOwned());
}

int
Test_WinPacketClone_SetUp(void **state)
{
    Saved_WinPacketRawAllocateClone = WinPacketRawAllocateClone_Callback;
    return 0;
}

int
Test_WinPacketClone_TearDown(void **state)
{
    WinPacketRawAllocateClone_Callback = Saved_WinPacketRawAllocateClone;
    return 0;
}

void
Test_WinPacketClone_ReturnsNullWhenCloneFails(void **state)
{
    WinPacketRawAllocateClone_Callback =
        Fake_WinPacketRawAllocateClone_ReturnsNull;

    PWIN_PACKET packet = Fake_WinPacketAllocateNonOwned();
    PWIN_PACKET_RAW rawPacket = WinPacketToRawPacket(packet);
    PWIN_PACKET cloned = WinPacketClone(packet);

    assert_null(cloned);
    assert_int_equal(WinPacketRawGetChildCountOf(rawPacket), 0);

    Fake_WinPacketFree(packet);
}

void
Test_WinPacketClone_ReturnsPacketWhenCloneSucceeds(void **state)
{
    WinPacketRawAllocateClone_Callback =
        Fake_WinPacketRawAllocateClone_ReturnsNewPacket;

    PWIN_PACKET packet = Fake_WinPacketAllocateNonOwned();
    PWIN_PACKET cloned = WinPacketClone(packet);

    PWIN_PACKET_RAW rawPacket = WinPacketToRawPacket(packet);
    PWIN_PACKET_RAW rawCloned = WinPacketToRawPacket(cloned);

    assert_non_null(rawCloned);
    assert_ptr_equal(WinPacketRawGetParentOf(rawCloned), rawPacket);
    assert_int_equal(WinPacketRawGetChildCountOf(rawPacket), 1);

    Fake_WinPacketFree(cloned);
    Fake_WinPacketFree(packet);
}

void
Test_WinPacketClone_RefCountIsValidAfterMultipleClones(void **state)
{
    WinPacketRawAllocateClone_Callback =
        Fake_WinPacketRawAllocateClone_ReturnsNewPacket;

    PWIN_PACKET packet = Fake_WinPacketAllocateNonOwned();

    PWIN_PACKET cloned1 = WinPacketClone(packet);
    PWIN_PACKET cloned2 = WinPacketClone(packet);
    PWIN_PACKET cloned3 = WinPacketClone(packet);

    PWIN_PACKET_RAW rawPacket = WinPacketToRawPacket(packet);
    PWIN_PACKET_RAW rawCloned1 = WinPacketToRawPacket(cloned1);
    PWIN_PACKET_RAW rawCloned2 = WinPacketToRawPacket(cloned2);
    PWIN_PACKET_RAW rawCloned3 = WinPacketToRawPacket(cloned3);

    assert_ptr_equal(WinPacketRawGetParentOf(rawCloned1), rawPacket);
    assert_ptr_equal(WinPacketRawGetParentOf(rawCloned2), rawPacket);
    assert_ptr_equal(WinPacketRawGetParentOf(rawCloned3), rawPacket);

    assert_int_equal(WinPacketRawGetChildCountOf(rawPacket), 3);
    assert_int_equal(WinPacketRawGetChildCountOf(rawCloned1), 0);
    assert_int_equal(WinPacketRawGetChildCountOf(rawCloned2), 0);
    assert_int_equal(WinPacketRawGetChildCountOf(rawCloned3), 0);

    Fake_WinPacketFree(cloned1);
    Fake_WinPacketFree(cloned2);
    Fake_WinPacketFree(cloned3);
    Fake_WinPacketFree(packet);
}

void
Test_WinPacketClone_RefCountIsValidAfterCloneOfClone(void **state)
{
    WinPacketRawAllocateClone_Callback =
        Fake_WinPacketRawAllocateClone_ReturnsNewPacket;

    PWIN_PACKET packet = Fake_WinPacketAllocateNonOwned();

    PWIN_PACKET cloned1 = WinPacketClone(packet);
    PWIN_PACKET cloned2 = WinPacketClone(cloned1);

    PWIN_PACKET_RAW rawPacket = WinPacketToRawPacket(packet);
    PWIN_PACKET_RAW rawCloned1 = WinPacketToRawPacket(cloned1);
    PWIN_PACKET_RAW rawCloned2 = WinPacketToRawPacket(cloned2);

    assert_ptr_equal(WinPacketRawGetParentOf(rawCloned1), rawPacket);
    assert_ptr_equal(WinPacketRawGetParentOf(rawCloned2), rawCloned1);

    assert_int_equal(WinPacketRawGetChildCountOf(rawPacket), 1);
    assert_int_equal(WinPacketRawGetChildCountOf(rawCloned1), 1);
    assert_int_equal(WinPacketRawGetChildCountOf(rawCloned2), 0);

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
