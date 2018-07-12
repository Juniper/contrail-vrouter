/*
 * test_win_packet_split_multi_packet.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "win_packet.h"
#include "fake_win_packet.h"

static PWIN_PACKET_LIST (*Saved_WinPacketListRawAllocateElement)();
static size_t WinPacketListRawAllocateElement_ValidCount;

PWIN_PACKET_LIST
Fake_WinPacketListRawAllocateElement_ReturnsNull()
{
    return NULL;
}

PWIN_PACKET_LIST
Fake_WinPacketListRawAllocateElement_ReturnsNullOnSelectedCall()
{
    if (WinPacketListRawAllocateElement_ValidCount == 0) {
        return NULL;
    }

    WinPacketListRawAllocateElement_ValidCount--;
    return test_calloc(1, sizeof(WIN_PACKET_LIST));
}

int
Test_WinPacketSplitMultiPacket_SetUp(void **state)
{
    Saved_WinPacketListRawAllocateElement = WinPacketListRawAllocateElement_Callback;
    return 0;
}

int
Test_WinPacketSplitMultiPacket_TearDown(void **state)
{
    WinPacketListRawAllocateElement_Callback = Saved_WinPacketListRawAllocateElement;
    return 0;
}

void
Test_WinPacketSplitMultiPacket_ReturnsNullWhenNoPacketsPassed(void **state)
{
    PWIN_MULTI_PACKET multiPacket = Fake_WinMultiPacketAllocateWithSubPackets(0);

    PWIN_PACKET_LIST packetList = WinPacketSplitMultiPacket(multiPacket);
    assert_null(packetList);

    Fake_WinMultiPacketFree(multiPacket, false);
}

void
Test_WinPacketSplitMultiPacket_ReturnsSinglePacketWhenSinglePacketPassed(void **state)
{
    PWIN_MULTI_PACKET multiPacket = Fake_WinMultiPacketAllocateWithSubPackets(1);
    PWIN_SUB_PACKET firstSubPacket = WinMultiPacketRawGetFirstSubPacket(multiPacket);

    PWIN_PACKET_LIST packetList = WinPacketSplitMultiPacket(multiPacket);

    assert_non_null(packetList);
    assert_ptr_equal(packetList->WinPacket, Fake_WinSubPacketToWinPacket(firstSubPacket));
    assert_null(packetList->Next);

    Fake_WinPacketListRawFree(packetList);
    Fake_WinMultiPacketFree(multiPacket, false);
}

void
Test_WinPacketSplitMultiPacket_ReturnsNullWhenErrorEncounteredWithSinglePacket(void **state)
{
    WinPacketListRawAllocateElement_Callback = Fake_WinPacketListRawAllocateElement_ReturnsNull;
    PWIN_MULTI_PACKET multiPacket = Fake_WinMultiPacketAllocateWithSubPackets(1);

    PWIN_PACKET_LIST packetList = WinPacketSplitMultiPacket(multiPacket);
    assert_null(packetList);

    Fake_WinMultiPacketFree(multiPacket, true);
}

void
Test_WinPacketSplitMultiPacket_ReturnsListWhenMultiplePacketsPassed(void **state)
{
    const int SUB_PACKETS_COUNT = 5;

    PWIN_MULTI_PACKET multiPacket = Fake_WinMultiPacketAllocateWithSubPackets(SUB_PACKETS_COUNT);
    PWIN_SUB_PACKET subPacket = WinMultiPacketRawGetFirstSubPacket(multiPacket);
    PWIN_SUB_PACKET subPacketPtr = subPacket;

    PWIN_PACKET_LIST packetList = WinPacketSplitMultiPacket(multiPacket);
    PWIN_PACKET_LIST packetListPtr = packetList;

    for (int i = 0; i < SUB_PACKETS_COUNT; ++i) {
        assert_non_null(packetListPtr);
        assert_ptr_equal(WinPacketRawGetParentOf(packetListPtr->WinPacket), Fake_WinSubPacketToWinPacket(subPacketPtr));

        packetListPtr = packetListPtr->Next;
        subPacketPtr = WinSubPacketRawGetNext(subPacketPtr);
    }

    assert_null(packetListPtr);
    assert_null(subPacketPtr);

    Fake_WinPacketListRawFree(packetList);
    Fake_WinMultiPacketFree(multiPacket, true);
}

void
Test_WinPacketSplitMultiPacket_ReturnsNullWhenErrorEncounteredWithMultiplePackets(void **state)
{
    const int SUB_PACKETS_COUNT = 5;
    WinPacketListRawAllocateElement_ValidCount = 3;
    WinPacketListRawAllocateElement_Callback = Fake_WinPacketListRawAllocateElement_ReturnsNullOnSelectedCall;
    PWIN_MULTI_PACKET multiPacket = Fake_WinMultiPacketAllocateWithSubPackets(SUB_PACKETS_COUNT);

    PWIN_PACKET_LIST packetList = WinPacketSplitMultiPacket(multiPacket);
    assert_null(packetList);

    Fake_WinMultiPacketFree(multiPacket, true);
}

#define WinPacketSplitMultiPacket_UnitTest_(p, f) cmocka_unit_test_setup_teardown(p##f, p##SetUp, p##TearDown)
#define WinPacketSplitMultiPacket_UnitTest(f) WinPacketSplitMultiPacket_UnitTest_(Test_WinPacketSplitMultiPacket_, f)

int main(void) {
    const struct CMUnitTest tests[] = {
        WinPacketSplitMultiPacket_UnitTest(ReturnsNullWhenNoPacketsPassed),
        WinPacketSplitMultiPacket_UnitTest(ReturnsSinglePacketWhenSinglePacketPassed),
        WinPacketSplitMultiPacket_UnitTest(ReturnsNullWhenErrorEncounteredWithSinglePacket),
        WinPacketSplitMultiPacket_UnitTest(ReturnsListWhenMultiplePacketsPassed),
        WinPacketSplitMultiPacket_UnitTest(ReturnsNullWhenErrorEncounteredWithMultiplePackets),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
