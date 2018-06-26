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
