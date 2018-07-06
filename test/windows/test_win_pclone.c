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
Fake_WinPacketRawAllocateClone_SetFailureOnNthCall(uint32_t N)
{
    RawAllocateClone_CalledCount = 0;
    RawAllocateClone_FirstFailure = N;
}

static PWIN_PACKET
Fake_WinPacketRawAllocateClone_Impl(PWIN_PACKET Packet)
{
    RawAllocateClone_CalledCount++;
    if (RawAllocateClone_CalledCount >= RawAllocateClone_FirstFailure) {
        return NULL;
    } else {
        return Fake_WinPacketAllocateOwned();
    }
}

extern PVOID (*WinRawAllocate_Callback)(size_t size);

static PVOID
Fake_WinRawAllocate_Null(size_t size)
{
    return NULL;
}

static struct vr_packet *
AllocateVrPacketNonOwned(VOID)
{
    PVR_PACKET_WRAPPER pkt = test_calloc(1, sizeof(*pkt));
    pkt->WinPacket = Fake_WinPacketAllocateNonOwned();
    return &pkt->VrPacket;
}

static VOID
FreeVrPacket(struct vr_packet * vrPkt)
{
    win_pfree(vrPkt, 0);
}

//Use _ suffix because there already exists "GetParent" function in WDK
static PWIN_PACKET
GetParent_(struct vr_packet * vrPkt)
{
    PWIN_PACKET winPacket = GetWinPacketFromVrPacket(vrPkt);
    return WinPacketRawGetParentOf(winPacket);
}

int
Test_win_pclone_SetUp(void **state)
{
    Saved_WinPacketRawAllocateClone = WinPacketRawAllocateClone_Callback;
    WinPacketRawAllocateClone_Callback = Fake_WinPacketRawAllocateClone_Impl;
    return 0;
}

int
Test_win_pclone_TearDown(void** state)
{
    WinPacketRawAllocateClone_Callback = Saved_WinPacketRawAllocateClone;
    return 0;
}

void
Test_win_pclone_ReturnsNullWhenNullIsPassed(void **state)
{
    expect_assert_failure(win_pclone(NULL));
}

void
Test_win_pclone_ReturnsNullWhenFirstCloneFails(void **state)
{
    WinPacketRawAllocateClone_Callback = Fake_WinPacketRawAllocateClone_Impl;
    Fake_WinPacketRawAllocateClone_SetFailureOnNthCall(1);

    struct vr_packet *vrPkt = AllocateVrPacketNonOwned();

    struct vr_packet *clonedVrPkt = win_pclone(vrPkt);
    assert_null(clonedVrPkt);

    FreeVrPacket(vrPkt);
}

void
Test_win_pclone_ReturnsNullWhenSecondCloneFails(void **state)
{
    WinPacketRawAllocateClone_Callback = Fake_WinPacketRawAllocateClone_Impl;
    Fake_WinPacketRawAllocateClone_SetFailureOnNthCall(2);

    struct vr_packet *vrPkt = AllocateVrPacketNonOwned();

    struct vr_packet *clonedVrPkt = win_pclone(vrPkt);
    assert_null(clonedVrPkt);

    FreeVrPacket(vrPkt);
}

void
Test_win_pclone_ReturnsNullWhenWrapperAllocationFails(void **state)
{
    Saved_WinRawAllocate = WinRawAllocate_Callback;
    WinRawAllocate_Callback = Fake_WinRawAllocate_Null;

    Fake_WinPacketRawAllocateClone_SetFailureOnNthCall(CLONE_MOCK_NEVER_FAILS);

    struct vr_packet *vrPkt = AllocateVrPacketNonOwned();

    struct vr_packet *clonedVrPkt = win_pclone(vrPkt);
    assert_null(clonedVrPkt);

    FreeVrPacket(vrPkt);

    WinRawAllocate_Callback = Saved_WinRawAllocate;
}

void
Test_win_pclone_ReturnsPacketWhenCloneSucceeds(void **state)
{
    Fake_WinPacketRawAllocateClone_SetFailureOnNthCall(CLONE_MOCK_NEVER_FAILS);

    struct vr_packet *vrPkt = AllocateVrPacketNonOwned();
    vrPkt->vp_type = 1;
    PWIN_PACKET originalWinPkt = GetWinPacketFromVrPacket(vrPkt);

    struct vr_packet *clonedVrPkt = win_pclone(vrPkt);
    assert_non_null(clonedVrPkt);

    assert_int_equal(WinPacketRawGetChildCountOf(originalWinPkt), 2);
    assert_ptr_equal(GetParent_(vrPkt), originalWinPkt);
    assert_ptr_equal(GetParent_(clonedVrPkt), originalWinPkt);
    assert_int_equal(clonedVrPkt->vp_type, 1);

    FreeVrPacket(vrPkt);
    FreeVrPacket(clonedVrPkt);
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
