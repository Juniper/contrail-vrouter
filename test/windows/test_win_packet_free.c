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

#define DEFINE_FAKE_CLEANUP_FUNC(FunctionName)                                 \
    static VOID (*Saved_WinPacketRaw ## FunctionName ## )(PWIN_PACKET Packet); \
    static PWIN_PACKET WinPacketRaw ## FunctionName ## Target;                 \
                                                                               \
    static VOID                                                                \
    Fake_WinPacketRaw ## FunctionName ## (PWIN_PACKET Packet)                  \
    {                                                                          \
        WinPacketRaw ## FunctionName ## Target = Packet;                       \
        Fake_WinPacketFree(Packet);                                            \
    }                                                                          \
                                                                               \
    static PWIN_PACKET                                                         \
    Fake_WinPacketRaw ## FunctionName ## _Target()                             \
    {                                                                          \
        return WinPacketRaw ## FunctionName ## Target;                         \
    }                                                                          \
                                                                               \
    static BOOL                                                                \
    Fake_WinPacketRaw ## FunctionName ## _WasCalled()                          \
    {                                                                          \
        return WinPacketRaw ## FunctionName ## Target != NULL;                 \
    }                                                                          \
                                                                               \
    struct _

#define SETUP_FAKE_CLEANUP_FUNC(FunctionName)                                  \
    do {                                                                       \
        Saved_WinPacketRaw ## FunctionName = WinPacketRaw ## FunctionName ## ; \
        WinPacketRaw ## FunctionName = Fake_WinPacketRaw ## FunctionName ## ;  \
        WinPacketRaw ## FunctionName ## Target = NULL;                         \
    } while (false)

#define TEARDOWN_FAKE_CLEANUP_FUNC(FunctionName)                               \
    do {                                                                       \
        WinPacketRaw ## FunctionName = Saved_WinPacketRaw ## FunctionName ## ; \
    } while (false)


DEFINE_FAKE_CLEANUP_FUNC(Complete);
DEFINE_FAKE_CLEANUP_FUNC(FreeCreated);
DEFINE_FAKE_CLEANUP_FUNC(FreeClone);

int
Test_WinPacketFree_SetUp(void **state)
{
    SETUP_FAKE_CLEANUP_FUNC(Complete);
    SETUP_FAKE_CLEANUP_FUNC(FreeCreated);
    SETUP_FAKE_CLEANUP_FUNC(FreeClone);

    return 0;
}

int
Test_WinPacketFree_TearDown(void **state)
{
    TEARDOWN_FAKE_CLEANUP_FUNC(Complete);
    TEARDOWN_FAKE_CLEANUP_FUNC(FreeCreated);
    TEARDOWN_FAKE_CLEANUP_FUNC(FreeClone);

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
    assert_false(Fake_WinPacketRawFreeCreated_WasCalled());
}

void
Test_WinPacketFree_NotOursWithChildrenAssertsOnChildCount(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocate();
    WinPacketRawIncrementChildCountOf(packet);
    Fake_WinPacketSetIsOwned(packet, FALSE);

    expect_assert_failure(WinPacketFree(packet));
    assert_false(Fake_WinPacketRawComplete_WasCalled());
    assert_false(Fake_WinPacketRawFreeCreated_WasCalled());

    Fake_WinPacketFree(packet);
}

void
Test_WinPacketFree_CreatedWithoutChildrenIsFreed(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocate();
    Fake_WinPacketSetIsOwned(packet, TRUE);

    WinPacketFree(packet);
    assert_false(Fake_WinPacketRawComplete_WasCalled());
    assert_true(Fake_WinPacketRawFreeCreated_WasCalled());
}

void
Test_WinPacketFree_CreatedWithChildrenAssertsOnChildCount(void **state)
{
    PWIN_PACKET packet = Fake_WinPacketAllocate();
    WinPacketRawIncrementChildCountOf(packet);
    Fake_WinPacketSetIsOwned(packet, TRUE);

    expect_assert_failure(WinPacketFree(packet));
    assert_false(Fake_WinPacketRawComplete_WasCalled());
    assert_false(Fake_WinPacketRawFreeCreated_WasCalled());

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
    assert_true(Fake_WinPacketRawFreeClone_WasCalled());
    assert_false(Fake_WinPacketRawFreeCreated_WasCalled());

    assert_ptr_equal(Fake_WinPacketRawComplete_Target(), parent);
    assert_ptr_equal(Fake_WinPacketRawFreeClone_Target(), cloned);
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
    assert_true(Fake_WinPacketRawFreeClone_WasCalled());
    assert_ptr_equal(Fake_WinPacketRawFreeClone_Target(), cloned2);

    WinPacketFree(cloned1);
    assert_true(Fake_WinPacketRawComplete_WasCalled());
    assert_true(Fake_WinPacketRawFreeClone_WasCalled());
    assert_ptr_equal(Fake_WinPacketRawFreeClone_Target(), cloned1);
    assert_ptr_equal(Fake_WinPacketRawComplete_Target(), parent);

    assert_false(Fake_WinPacketRawFreeCreated_WasCalled());
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
    assert_false(Fake_WinPacketRawFreeCreated_WasCalled());

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
    assert_true(Fake_WinPacketRawFreeClone_WasCalled());
    assert_false(Fake_WinPacketRawFreeCreated_WasCalled());
    assert_int_equal(WinPacketRawGetChildCountOf(parent), 0);

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

    WinPacketFree(tree->lowerChild1);

    assert_false(Fake_WinPacketRawComplete_WasCalled());
    assert_false(Fake_WinPacketRawFreeCreated_WasCalled());
    assert_true(Fake_WinPacketRawFreeClone_WasCalled());
    assert_ptr_equal(Fake_WinPacketRawFreeClone_Target(), tree->lowerChild1);

    assert_int_equal(WinPacketRawGetChildCountOf(tree->parent), 2);
    assert_int_equal(WinPacketRawGetChildCountOf(tree->upperChild1), 1);
    assert_int_equal(WinPacketRawGetChildCountOf(tree->upperChild2), 1);

    tree->lowerChild1 = NULL;

    WinPacketsTreeFree(packets);
}

void
Test_WinPacketFree_TreeAllLowerChildrenOfOneUpperChild(void **state)
{
    PPACKETS packets = WinPacketsTreeAllocate();
    PPACKET_TREE tree = &packets->tree;

    WinPacketFree(tree->lowerChild1);
    WinPacketFree(tree->lowerChild2);

    assert_false(Fake_WinPacketRawComplete_WasCalled());
    assert_false(Fake_WinPacketRawFreeCreated_WasCalled());
    assert_true(Fake_WinPacketRawFreeClone_WasCalled());
    assert_ptr_equal(Fake_WinPacketRawFreeClone_Target(), tree->upperChild1);

    assert_int_equal(WinPacketRawGetChildCountOf(tree->parent), 1);
    assert_int_equal(WinPacketRawGetChildCountOf(tree->upperChild2), 1);

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

    WinPacketFree(tree->lowerChild1);
    WinPacketFree(tree->lowerChild2);
    WinPacketFree(tree->lowerChild3);

    assert_true(Fake_WinPacketRawComplete_WasCalled());
    assert_false(Fake_WinPacketRawFreeCreated_WasCalled());
    assert_true(Fake_WinPacketRawFreeClone_WasCalled());
    assert_ptr_equal(Fake_WinPacketRawFreeClone_Target(), tree->upperChild2);
    assert_ptr_equal(Fake_WinPacketRawComplete_Target(), tree->parent);

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

        WinPacketFree_UnitTest(ClonedPreservingParent_Works),

        WinPacketFree_UnitTest(TreeSingleLowerChild),
        WinPacketFree_UnitTest(TreeAllLowerChildrenOfOneUpperChild),
        WinPacketFree_UnitTest(TreeAllLowerChildrenOfAllUpperChildren),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
