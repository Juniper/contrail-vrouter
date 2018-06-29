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
#include "fake_win_packet.h"

static VOID (*Saved_WinPacketRawComplete)(PWIN_PACKET Packet);
static VOID (*Saved_WinPacketRawFreeCreated)(PWIN_PACKET Packet);

static PWIN_PACKET WinPacketRawCompleteTarget;

static bool WasWinPacketRawFreeCreatedCalled;

static VOID
Fake_WinPacketRawComplete(PWIN_PACKET Packet)
{
    WinPacketRawCompleteTarget = Packet;
    Fake_WinPacketFree(Packet);
}

static PWIN_PACKET
Fake_WinPacketRawComplete_Target()
{
    return WinPacketRawCompleteTarget;
}

static BOOL
Fake_WinPacketRawComplete_WasCalled()
{
    return WinPacketRawCompleteTarget != NULL;
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
    Saved_WinPacketRawComplete = WinPacketRawComplete;
    WinPacketRawComplete = Fake_WinPacketRawComplete;
    WinPacketRawCompleteTarget = NULL;

    Saved_WinPacketRawFreeCreated = WinPacketRawFreeCreated;
    WinPacketRawFreeCreated = Fake_WinPacketRawFreeCreated;
    WasWinPacketRawFreeCreatedCalled = FALSE;

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

    WinPacketFree(packet);
    assert_true(Fake_WinPacketRawComplete_WasCalled());
    assert_ptr_equal(Fake_WinPacketRawComplete_Target(), packet);
    assert_false(WasWinPacketRawFreeCreatedCalled);
}

void
Test_WinPacketFree_NotOursWithChildrenAssertsOnChildCount(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocate();
    WinPacketRawIncrementChildCountOf(packet);
    Fake_WinPacketSetIsOwned(packet, FALSE);

    expect_assert_failure(WinPacketFree(packet));
    assert_false(Fake_WinPacketRawComplete_WasCalled());
    assert_false(WasWinPacketRawFreeCreatedCalled);

    Fake_WinPacketFree(packet);
}

void
Test_WinPacketFree_CreatedWithoutChildrenIsFreed(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocate();
    Fake_WinPacketSetIsOwned(packet, TRUE);

    WinPacketFree(packet);
    assert_false(Fake_WinPacketRawComplete_WasCalled());
    assert_true(WasWinPacketRawFreeCreatedCalled);
}

void
Test_WinPacketFree_CreatedWithChildrenAssertsOnChildCount(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocate();
    WinPacketRawIncrementChildCountOf(packet);
    Fake_WinPacketSetIsOwned(packet, TRUE);

    expect_assert_failure(WinPacketFree(packet));
    assert_false(Fake_WinPacketRawComplete_WasCalled());
    assert_false(WasWinPacketRawFreeCreatedCalled);

    Fake_WinPacketFree(packet);
}

void
Test_WinPacketFree_ClonedWithoutChildren_ParentIsFreed(void **state)
{
    PWIN_PACKET parent = Fake_WinPacketAllocate();
    Fake_WinPacketSetIsOwned(parent, FALSE);

    PWIN_PACKET cloned = WinPacketClone(parent);
    Fake_WinPacketSetIsOwned(cloned, TRUE);

    WinPacketFree(cloned);
    assert_true(Fake_WinPacketRawComplete_WasCalled());
    assert_ptr_equal(Fake_WinPacketRawComplete_Target(), parent);
}

void
Test_WinPacketFree_ClonedWithoutChildren_ParentIsNotFreedWhenMultipleChildren(void **state)
{
    PWIN_PACKET parent = Fake_WinPacketAllocate();
    Fake_WinPacketSetIsOwned(parent, FALSE);

    PWIN_PACKET cloned1 = WinPacketClone(parent);
    Fake_WinPacketSetIsOwned(cloned1, TRUE);

    PWIN_PACKET cloned2 = WinPacketClone(parent);
    Fake_WinPacketSetIsOwned(cloned2, TRUE);

    WinPacketFree(cloned2);
    assert_false(Fake_WinPacketRawComplete_WasCalled());

    WinPacketFree(cloned1);
    assert_true(Fake_WinPacketRawComplete_WasCalled());
    assert_ptr_equal(Fake_WinPacketRawComplete_Target(), parent);
}

static PWIN_PACKET
Fake_WinPacketAllocate_ClonedWithChildren()
{
    PWIN_PACKET badParent = (PWIN_PACKET)~0;

    PWIN_PACKET packet = Fake_WinPacketAllocate();
    WinPacketRawSetParentOf(packet, badParent);
    WinPacketRawIncrementChildCountOf(packet);
    Fake_WinPacketSetIsOwned(packet, TRUE);

    return packet;
}

void
Test_WinPacketFree_ClonedWithChildrenAssertsOnChildCount(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocate_ClonedWithChildren();

    expect_assert_failure(WinPacketFree(packet));
    assert_false(Fake_WinPacketRawComplete_WasCalled());
    assert_false(WasWinPacketRawFreeCreatedCalled);

    Fake_WinPacketFree(packet);
}

void
Test_WinPacketFree_ClonedPreservingParent_Works(void **state)
{
    PWIN_PACKET parent = Fake_WinPacketAllocate();
    Fake_WinPacketSetIsOwned(parent, FALSE);

    PWIN_PACKET cloned = WinPacketClone(parent);
    Fake_WinPacketSetIsOwned(cloned, TRUE);
    assert_int_equal(WinPacketRawGetChildCountOf(parent), 1);

    WinPacketFreeClonedPreservingParent(cloned);
    assert_false(Fake_WinPacketRawComplete_WasCalled());
    assert_int_equal(WinPacketRawGetChildCountOf(parent), 0);

    Fake_WinPacketFree(parent);
}

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
    PWIN_PACKET array[16];
} PACKETS, *PPACKETS;

static PACKETS test_packets_structure;

void
Test_WinPacketFreeTree_SetUp(void** state) {
    PPACKETS packets = &test_packets_structure;
    memset(packets, 0, sizeof(*packets));

    PPACKET_TREE tree = &packets->tree;

    tree->parent = Fake_WinPacketAllocate();
    Fake_WinPacketSetIsOwned(tree->parent, FALSE);

    tree->upperChild1 = WinPacketClone(tree->parent);
    Fake_WinPacketSetIsOwned(tree->upperChild1, TRUE);

    tree->upperChild2 = WinPacketClone(tree->parent);
    Fake_WinPacketSetIsOwned(tree->upperChild2, TRUE);

    tree->lowerChild1 = WinPacketClone(tree->upperChild1);
    Fake_WinPacketSetIsOwned(tree->lowerChild1, TRUE);

    tree->lowerChild2 = WinPacketClone(tree->upperChild1);
    Fake_WinPacketSetIsOwned(tree->lowerChild2, TRUE);

    tree->lowerChild3 = WinPacketClone(tree->upperChild2);
    Fake_WinPacketSetIsOwned(tree->lowerChild3, TRUE);

    *state = &tree;
}

void
Test_WinPacketFreeTree_TearDown(void** state)
{
    PPACKETS packets = &test_packets_structure;

    for (int i = 0; i < 16; ++i) {
        if (packets->array[i] != NULL) {
            Fake_WinPacketFree(packets->array[i]);
        }
    }
}

void
Test_WinPacketFree_ClonedTreeStructure(void **state)
{
    PWIN_PACKET parent = Fake_WinPacketAllocate();
    Fake_WinPacketSetIsOwned(parent, FALSE);

    PWIN_PACKET upperChild1 = WinPacketClone(parent);
    Fake_WinPacketSetIsOwned(upperChild1, TRUE);

    PWIN_PACKET upperChild2 = WinPacketClone(parent);
    Fake_WinPacketSetIsOwned(upperChild2, TRUE);

    PWIN_PACKET lowerChild1 = WinPacketClone(upperChild1);
    Fake_WinPacketSetIsOwned(lowerChild1, TRUE);

    PWIN_PACKET lowerChild2 = WinPacketClone(upperChild1);
    Fake_WinPacketSetIsOwned(lowerChild2, TRUE);

    PWIN_PACKET lowerChild3 = WinPacketClone(upperChild2);
    Fake_WinPacketSetIsOwned(lowerChild3, TRUE);

    assert_int_equal(WinPacketRawGetChildCountOf(parent), 2);
    assert_int_equal(WinPacketRawGetChildCountOf(upperChild1), 2);
    assert_int_equal(WinPacketRawGetChildCountOf(upperChild2), 1);

    WinPacketFree(lowerChild1);

    assert_true(Fake_WinPacketRawComplete_WasCalled());
    assert_int_equal(WinPacketRawGetChildCountOf(parent), 2);
    assert_int_equal(WinPacketRawGetChildCountOf(upperChild1), 1);
    assert_int_equal(WinPacketRawGetChildCountOf(upperChild2), 1);

    Fake_WinPacketFree(lowerChild2);
    Fake_WinPacketFree(lowerChild3);
    Fake_WinPacketFree(upperChild2);
    Fake_WinPacketFree(upperChild1);
    Fake_WinPacketFree(parent);
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
        WinPacketFree_UnitTest(ClonedTreeStructure),

        WinPacketFree_UnitTest(ClonedPreservingParent_Works),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
