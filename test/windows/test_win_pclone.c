/*
 * test_win_pclone.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "vr_packet.h"
#include "win_packet.h"
#include "fake_win_packet.h"

extern struct vr_packet *win_pclone(struct vr_packet *pkt);

static PWIN_PACKET (*Saved_WinPacketRawAllocateClone)(PWIN_PACKET Packet);
static PVOID (*Saved_WinRawAllocate)(size_t size);

#define CLONE_MOCK_NEVER_FAILS (UINT32_MAX)

static uint32_t RawAllocateClone_CalledCount;
static uint32_t RawAllocateClone_FirstFailure;

static void
Fake_WinPacketRawAllocateClone_SetupMock(uint32_t FirstFailure)
{
    RawAllocateClone_CalledCount = 0;
    RawAllocateClone_FirstFailure = FirstFailure;
}

static void
Fake_WinPacketRawAllocateClone_VerifyCalledCount(uint32_t CalledCount)
{
    assert_int_equal(RawAllocateClone_CalledCount, CalledCount);
}

static PWIN_PACKET
Fake_WinPacketRawAllocateClone_Impl(PWIN_PACKET Packet)
{
    RawAllocateClone_CalledCount++;
    if (RawAllocateClone_CalledCount >= RawAllocateClone_FirstFailure) {
        return NULL;
    } else {
        return Fake_WinPacketAllocate();
    }
}

static PVOID
Fake_WinRawAllocate_Impl(size_t size)
{
    return test_calloc(1, size);
}

PVOID (*WinRawAllocate)(size_t size) = Fake_WinRawAllocate_Impl;

static PVOID
Fake_WinRawAllocate_Null(size_t size)
{
    return NULL;
}

static struct vr_packet *
Test_AllocateVrPacket(VOID)
{
    PVR_PACKET_WRAPPER pkt = test_calloc(1, sizeof(*pkt));
    pkt->WinPacket = Fake_WinPacketAllocate();
    return &pkt->VrPacket;
}

static VOID
Test_FreeVrPacket(struct vr_packet * vrPkt)
{
    PVR_PACKET_WRAPPER pkt = GetWrapperFromVrPacket(vrPkt);
    Fake_WinPacketFree(pkt->WinPacket);
    test_free(pkt);
}

static LONG
Test_UnwrapChildCount(struct vr_packet * vrPkt)
{
    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(vrPkt);
    return WinPacketRawGetChildCountOf(winPacket);
}

static PWIN_PACKET
Test_UnwrapParent(struct vr_packet * vrPkt)
{
    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(vrPkt);
    return WinPacketRawGetParentOf(winPacket);
}

int
Test_win_pclone_SetUp(void **state)
{
    Saved_WinPacketRawAllocateClone = WinPacketRawAllocateClone;
    WinPacketRawAllocateClone = Fake_WinPacketRawAllocateClone_Impl;
    return 0;
}

int
Test_win_pclone_TearDown(void** state)
{
    WinPacketRawAllocateClone = Saved_WinPacketRawAllocateClone;
    return 0;
}

void
Test_win_pclone_ReturnsNullWhenNullIsPassed(void **state)
{
    assert_null(win_pclone(NULL));
}

void
Test_win_pclone_ReturnsNullWhenFirstCloneFails(void **state)
{
    Fake_WinPacketRawAllocateClone_SetupMock(1);

    struct vr_packet *vrPkt = Test_AllocateVrPacket();

    struct vr_packet *clonedVrPkt = win_pclone(vrPkt);
    assert_null(clonedVrPkt);

    Fake_WinPacketRawAllocateClone_VerifyCalledCount(1);
    assert_int_equal(Test_UnwrapChildCount(vrPkt), 0);

    Test_FreeVrPacket(vrPkt);
}

void
Test_win_pclone_ReturnsNullWhenSecondCloneFails(void **state)
{
    Fake_WinPacketRawAllocateClone_SetupMock(2);

    struct vr_packet *vrPkt = Test_AllocateVrPacket();

    struct vr_packet *clonedVrPkt = win_pclone(vrPkt);
    assert_null(clonedVrPkt);

    Fake_WinPacketRawAllocateClone_VerifyCalledCount(2);
    assert_int_equal(Test_UnwrapChildCount(vrPkt), 0);

    Test_FreeVrPacket(vrPkt);
}

void
Test_win_pclone_ReturnsNullWhenWrapperAllocationFails(void **state)
{
    Saved_WinRawAllocate = WinRawAllocate;
    WinRawAllocate = Fake_WinRawAllocate_Null;

    Fake_WinPacketRawAllocateClone_SetupMock(CLONE_MOCK_NEVER_FAILS);

    struct vr_packet *vrPkt = Test_AllocateVrPacket();

    struct vr_packet *clonedVrPkt = win_pclone(vrPkt);
    assert_null(clonedVrPkt);

    Fake_WinPacketRawAllocateClone_VerifyCalledCount(2);
    assert_int_equal(Test_UnwrapChildCount(vrPkt), 0);

    Test_FreeVrPacket(vrPkt);

    WinRawAllocate = Saved_WinRawAllocate;
}

void
Test_win_pclone_ReturnsPacketWhenCloneSucceeds(void **state)
{
    Fake_WinPacketRawAllocateClone_SetupMock(CLONE_MOCK_NEVER_FAILS);

    struct vr_packet *vrPkt = Test_AllocateVrPacket();
    vrPkt->vp_type = 1;
    PWIN_PACKET originalWinPkt = GetWinPacketFromVrPacket(vrPkt);

    struct vr_packet *clonedVrPkt = win_pclone(vrPkt);
    assert_non_null(clonedVrPkt);

    Fake_WinPacketRawAllocateClone_VerifyCalledCount(2);
    assert_int_equal(WinPacketRawGetChildCountOf(originalWinPkt), 2);
    assert_int_equal(Test_UnwrapChildCount(vrPkt), 0);
    assert_int_equal(Test_UnwrapChildCount(clonedVrPkt), 0);
    assert_ptr_equal(Test_UnwrapParent(vrPkt), originalWinPkt);
    assert_ptr_equal(Test_UnwrapParent(clonedVrPkt), originalWinPkt);
    assert_int_equal(clonedVrPkt->vp_type, 1);

    Test_FreeVrPacket(vrPkt);
    Test_FreeVrPacket(clonedVrPkt);

    Fake_WinPacketFree(originalWinPkt);
}

#define win_pclone_UnitTest_(p, f) cmocka_unit_test_setup_teardown(p##f, p##SetUp, p##TearDown)
#define win_pclone_UnitTest(f) win_pclone_UnitTest_(Test_win_pclone_, f)

int main(void) {
    const struct CMUnitTest tests[] = {
        win_pclone_UnitTest(ReturnsNullWhenNullIsPassed),
        win_pclone_UnitTest(ReturnsNullWhenFirstCloneFails),
        win_pclone_UnitTest(ReturnsNullWhenSecondCloneFails),
        win_pclone_UnitTest(ReturnsNullWhenWrapperAllocationFails),
        win_pclone_UnitTest(ReturnsPacketWhenCloneSucceeds),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
