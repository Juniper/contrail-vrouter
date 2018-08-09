/*
 * test_win_packet_free.c
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

static void
Fake_WinPacketRawComplete(PWIN_PACKET_RAW Packet)
{
    assert_false(WinPacketRawIsOwned(Packet));
    assert_false(WinPacketRawIsCloned(Packet));

    Fake_WinPacketFree((PWIN_PACKET)Packet);
}
static void (*Saved_WinPacketRawComplete)(PWIN_PACKET_RAW Packet);

static void
Fake_WinPacketRawFreeCreated(PWIN_PACKET_RAW Packet)
{
    assert_true(WinPacketRawIsOwned(Packet));
    assert_false(WinPacketRawIsCloned(Packet));
    assert_false(WinPacketRawIsMultiFragment(Packet));

    Fake_WinPacketFree((PWIN_PACKET)Packet);
}
static void (*Saved_WinPacketRawFreeCreated)(PWIN_PACKET_RAW Packet);

static void
Fake_WinPacketRawFreeClone(PWIN_PACKET_RAW Packet)
{
    assert_true(WinPacketRawIsOwned(Packet));
    assert_true(WinPacketRawIsCloned(Packet));
    assert_false(WinPacketRawIsMultiFragment(Packet));

    Fake_WinPacketFree((PWIN_PACKET)Packet);
}
static void (*Saved_WinPacketRawFreeClone)(PWIN_PACKET_RAW Packet);

static void
Fake_WinPacketRawFreeMultiFragment(PWIN_PACKET_RAW Packet)
{
    assert_true(WinPacketRawIsOwned(Packet));
    assert_true(WinPacketRawIsCloned(Packet));
    assert_true(WinPacketRawIsMultiFragment(Packet));

    Fake_WinPacketFree((PWIN_PACKET)Packet);
}
static void (*Saved_WinPacketRawFreeMultiFragment)(PWIN_PACKET_RAW Packet);

int
Test_WinPacketFree_SetUp(void **state)
{
    Saved_WinPacketRawComplete = WinPacketRawComplete_Callback;
    WinPacketRawComplete_Callback = Fake_WinPacketRawComplete;

    Saved_WinPacketRawFreeCreated = WinPacketRawFreeCreated_Callback;
    WinPacketRawFreeCreated_Callback = Fake_WinPacketRawFreeCreated;

    Saved_WinPacketRawFreeClone = WinPacketRawFreeClone_Callback;
    WinPacketRawFreeClone_Callback = Fake_WinPacketRawFreeClone;

    Saved_WinPacketRawFreeMultiFragment
        = WinPacketRawFreeMultiFragment_Callback;
    WinPacketRawFreeMultiFragment_Callback = Fake_WinPacketRawFreeMultiFragment;

    return 0;
}

int
Test_WinPacketFree_TearDown(void **state)
{
    WinPacketRawComplete_Callback = Saved_WinPacketRawComplete;
    WinPacketRawFreeCreated_Callback = Saved_WinPacketRawFreeCreated;
    WinPacketRawFreeClone_Callback = Saved_WinPacketRawFreeClone;
    WinPacketRawFreeMultiFragment_Callback
        = Saved_WinPacketRawFreeMultiFragment;

    return 0;
}

void
Test_WinPacketFree_NotOursWithoutChildrenIsCompleted(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocateNonOwned();

    WinPacketFreeRecursive(packet);
}

void
Test_WinPacketFree_NotOursWithChildrenAssertsOnChildCount(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocateNonOwned();
    PWIN_PACKET_RAW rawPacket = WinPacketToRawPacket(packet);
    WinPacketRawIncrementChildCountOf(rawPacket);

    expect_assert_failure(WinPacketFreeRecursive(packet));

    Fake_WinPacketFree(packet);
}

void
Test_WinPacketFree_CreatedWithoutChildrenIsFreed(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocateOwned();

    WinPacketFreeRecursive(packet);
}

void
Test_WinPacketFree_CreatedWithChildrenAssertsOnChildCount(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocateOwned();
    PWIN_PACKET_RAW rawPacket = WinPacketToRawPacket(packet);
    WinPacketRawIncrementChildCountOf(rawPacket);

    expect_assert_failure(WinPacketFreeRecursive(packet));

    Fake_WinPacketFree(packet);
}

void
Test_WinPacketFree_ClonedWithoutChildren_ParentIsFreed(void **state)
{
    PWIN_PACKET parent = Fake_WinPacketAllocateNonOwned();
    PWIN_PACKET cloned = WinPacketClone(parent);

    WinPacketFreeRecursive(cloned);
}

void
Test_WinPacketFree_ClonedWithoutChildren_ParentIsNotFreedWhenMultipleChildren(void **state)
{
    PWIN_PACKET parent = Fake_WinPacketAllocateNonOwned();
    PWIN_PACKET cloned1 = WinPacketClone(parent);
    PWIN_PACKET cloned2 = WinPacketClone(parent);

    WinPacketFreeRecursive(cloned2);
    WinPacketFreeRecursive(cloned1);
}

static PWIN_PACKET
Fake_WinPacketAllocate_ClonedWithChildren()
{
    PWIN_PACKET_RAW badParent = (PWIN_PACKET_RAW)~0;

    PWIN_PACKET packet = Fake_WinPacketAllocateOwned();
    PWIN_PACKET_RAW rawPacket = WinPacketToRawPacket(packet);
    WinPacketRawSetParentOf(rawPacket, badParent);
    WinPacketRawIncrementChildCountOf(rawPacket);

    return packet;
}

void
Test_WinPacketFree_ClonedWithChildrenAssertsOnChildCount(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocate_ClonedWithChildren();

    expect_assert_failure(WinPacketFreeRecursive(packet));

    Fake_WinPacketFree(packet);
}

void
Test_WinPacketFree_FragmentedIsFreed(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocateMultiFragment();
    WinPacketFreeRecursive(packet);
}

void
Test_WinPacketFree_ClonedPreservingParent_Works(void **state)
{
    PWIN_PACKET parent = Fake_WinPacketAllocateNonOwned();
    PWIN_PACKET_RAW rawParent = WinPacketToRawPacket(parent);
    PWIN_PACKET cloned = WinPacketClone(parent);

    assert_int_equal(WinPacketRawGetChildCountOf(rawParent), 1);

    WinPacketFreeClonedPreservingParent(cloned);
    assert_int_equal(WinPacketRawGetChildCountOf(rawParent), 0);

    Fake_WinPacketFree(parent);
}

enum { PACKETS_MAX_COUNT = 16 };

typedef struct _PACKET_TREE {
    PWIN_PACKET parent;

    PWIN_PACKET upperChild1;
    PWIN_PACKET upperChild2;

    PWIN_PACKET lowerChild1;
    PWIN_PACKET lowerChild2;
    PWIN_PACKET lowerChild3;
} PACKET_TREE, *PPACKET_TREE;

typedef union {
    PACKET_TREE tree;
    PWIN_PACKET array[PACKETS_MAX_COUNT];
} PACKETS, *PPACKETS;

PPACKETS
WinPacketsTreeAllocate() {
    PPACKETS packets = test_calloc(1, sizeof(*packets));
    PPACKET_TREE tree = &packets->tree;

    tree->parent = Fake_WinPacketAllocateNonOwned();
    tree->upperChild1 = WinPacketClone(tree->parent);
    tree->upperChild2 = WinPacketClone(tree->parent);
    tree->lowerChild1 = WinPacketClone(tree->upperChild1);
    tree->lowerChild2 = WinPacketClone(tree->upperChild1);
    tree->lowerChild3 = WinPacketClone(tree->upperChild2);

    return packets;
}

void
WinPacketsTreeFree(PPACKETS Packets)
{
    for (int i = 0; i < PACKETS_MAX_COUNT; ++i) {
        if (Packets->array[i] != NULL) {
            Fake_WinPacketFree(Packets->array[i]);
            Packets->array[i] = NULL;
        }
    }

    test_free(Packets);
}

void
Test_WinPacketFree_TreeSingleLowerChild(void **state)
{
    PPACKETS packets = WinPacketsTreeAllocate();
    PPACKET_TREE tree = &packets->tree;

    WinPacketFreeRecursive(tree->lowerChild1);

    assert_int_equal(WinPacketRawGetChildCountOf(WinPacketToRawPacket(tree->parent)), 2);
    assert_int_equal(WinPacketRawGetChildCountOf(WinPacketToRawPacket(tree->upperChild1)), 1);
    assert_int_equal(WinPacketRawGetChildCountOf(WinPacketToRawPacket(tree->upperChild2)), 1);

    tree->lowerChild1 = NULL;

    WinPacketsTreeFree(packets);
}

void
Test_WinPacketFree_TreeAllLowerChildrenOfOneUpperChild(void **state)
{
    PPACKETS packets = WinPacketsTreeAllocate();
    PPACKET_TREE tree = &packets->tree;

    WinPacketFreeRecursive(tree->lowerChild1);
    WinPacketFreeRecursive(tree->lowerChild2);

    assert_int_equal(WinPacketRawGetChildCountOf(WinPacketToRawPacket(tree->parent)), 1);
    assert_int_equal(WinPacketRawGetChildCountOf(WinPacketToRawPacket(tree->upperChild2)), 1);

    tree->lowerChild1 = NULL;
    tree->lowerChild2 = NULL;
    tree->upperChild1 = NULL;

    WinPacketsTreeFree(packets);
}

void
Test_WinPacketFree_TreeAllLowerChildrenOfAllUpperChildren(void **state)
{
    PPACKETS packets = WinPacketsTreeAllocate();
    PPACKET_TREE tree = &packets->tree;

    WinPacketFreeRecursive(tree->lowerChild1);
    WinPacketFreeRecursive(tree->lowerChild2);
    WinPacketFreeRecursive(tree->lowerChild3);

    for (int i = 0; i < PACKETS_MAX_COUNT; ++i) {
        packets->array[i] = NULL;
    }

    WinPacketsTreeFree(packets);
}

#define WinPacketFree_UnitTest_(p, f) cmocka_unit_test_setup_teardown(p##f, p##SetUp, p##TearDown)
#define WinPacketFree_UnitTest(f) WinPacketFree_UnitTest_(Test_WinPacketFree_, f)

int main(void) {
    const struct CMUnitTest tests[] = {
        WinPacketFree_UnitTest(NotOursWithoutChildrenIsCompleted),
        WinPacketFree_UnitTest(NotOursWithChildrenAssertsOnChildCount),

        WinPacketFree_UnitTest(CreatedWithoutChildrenIsFreed),
        WinPacketFree_UnitTest(CreatedWithChildrenAssertsOnChildCount),

        WinPacketFree_UnitTest(ClonedWithoutChildren_ParentIsFreed),
        WinPacketFree_UnitTest(ClonedWithoutChildren_ParentIsNotFreedWhenMultipleChildren),
        WinPacketFree_UnitTest(ClonedWithChildrenAssertsOnChildCount),

        WinPacketFree_UnitTest(FragmentedIsFreed),

        WinPacketFree_UnitTest(ClonedPreservingParent_Works),

        WinPacketFree_UnitTest(TreeSingleLowerChild),
        WinPacketFree_UnitTest(TreeAllLowerChildrenOfOneUpperChild),
        WinPacketFree_UnitTest(TreeAllLowerChildrenOfAllUpperChildren),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
