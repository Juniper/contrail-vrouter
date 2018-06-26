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

    PWIN_PACKET packet = Fake_WinPacketAllocate();
    *state = packet;

    return 0;
}

int
Test_WinPacketClone_TearDown(void **state)
{
    PWIN_PACKET packet = *state;
    Fake_WinPacketFree(packet);

    WinPacketRawAllocateClone = Saved_WinPacketRawAllocateClone;

    return 0;
}

void
Test_WinPacketClone_ReturnsNullWhenCloneFails(void **state)
{
    WinPacketRawAllocateClone = Fake_WinPacketRawAllocateClone_ReturnsNull;

    PWIN_PACKET packet = *state;
    PWIN_PACKET cloned = WinPacketClone(packet);
    assert_null(cloned);
    assert_true(WinPacketRawGetChildCountOf(packet) == 0);
}

void
Test_WinPacketClone_ReturnsPacketWhenCloneSucceeds(void **state)
{
    WinPacketRawAllocateClone = Fake_WinPacketRawAllocateClone_ReturnsNewPacket;

    PWIN_PACKET packet = *state;
    PWIN_PACKET cloned = WinPacketClone(packet);
    assert_non_null(cloned);
    assert_true(WinPacketRawGetParentOf(cloned) == packet);
    assert_true(WinPacketRawGetChildCountOf(packet) == 1);
    Fake_WinPacketFree(cloned);
}

void
Test_WinPacketClone_RefCountIsValidAfterMultipleClones(void **state)
{
    WinPacketRawAllocateClone = Fake_WinPacketRawAllocateClone_ReturnsNewPacket;

    PWIN_PACKET packet = *state;

    PWIN_PACKET cloned1 = WinPacketClone(packet);
    PWIN_PACKET cloned2 = WinPacketClone(packet);
    PWIN_PACKET cloned3 = WinPacketClone(packet);

    assert_true(WinPacketRawGetParentOf(cloned1) == packet);
    assert_true(WinPacketRawGetParentOf(cloned2) == packet);
    assert_true(WinPacketRawGetParentOf(cloned3) == packet);

    assert_true(WinPacketRawGetChildCountOf(packet) == 3);
    assert_true(WinPacketRawGetChildCountOf(cloned1) == 0);
    assert_true(WinPacketRawGetChildCountOf(cloned2) == 0);
    assert_true(WinPacketRawGetChildCountOf(cloned3) == 0);

    Fake_WinPacketFree(cloned1);
    Fake_WinPacketFree(cloned2);
    Fake_WinPacketFree(cloned3);
}

void
Test_WinPacketClone_RefCountIsValidAfterCloneOfClone(void **state)
{
    WinPacketRawAllocateClone = Fake_WinPacketRawAllocateClone_ReturnsNewPacket;

    PWIN_PACKET packet = *state;

    PWIN_PACKET cloned1 = WinPacketClone(packet);
    PWIN_PACKET cloned2 = WinPacketClone(cloned1);

    assert_true(WinPacketRawGetParentOf(cloned1) == packet);
    assert_true(WinPacketRawGetParentOf(cloned2) == cloned1);

    assert_true(WinPacketRawGetChildCountOf(packet) == 1);
    assert_true(WinPacketRawGetChildCountOf(cloned1) == 1);
    assert_true(WinPacketRawGetChildCountOf(cloned2) == 0);

    Fake_WinPacketFree(cloned2);
    Fake_WinPacketFree(cloned1);
}
