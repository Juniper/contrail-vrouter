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
    assert_true(RawAllocateClone_CalledCount == CalledCount);
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

void
Test_win_pclone_ReturnsNullWhenNullIsPassed(void **state)
{
    assert_true(win_pclone(NULL) == NULL);
}

void
Test_win_pclone_ReturnsNullWhenFirstCloneFails(void **state)
{
    Saved_WinPacketRawAllocateClone = WinPacketRawAllocateClone;
    WinPacketRawAllocateClone = Fake_WinPacketRawAllocateClone_Impl;

    Fake_WinPacketRawAllocateClone_SetupMock(1);

    PVR_PACKET_WRAPPER pkt = test_calloc(1, sizeof(*pkt));
    pkt->WinPacket = Fake_WinPacketAllocate();
    struct vr_packet *vrPkt = &pkt->VrPacket;

    struct vr_packet *clonedVrPkt = win_pclone(vrPkt);
    assert_null(clonedVrPkt);

    Fake_WinPacketRawAllocateClone_VerifyCalledCount(1);
    assert_true(WinPacketRawGetChildCountOf(pkt->WinPacket) == 0);

    Fake_WinPacketFree(pkt->WinPacket);
    test_free(pkt);

    WinPacketRawAllocateClone = Saved_WinPacketRawAllocateClone;
}

void
Test_win_pclone_ReturnsNullWhenSecondCloneFails(void **state)
{
    Saved_WinPacketRawAllocateClone = WinPacketRawAllocateClone;
    WinPacketRawAllocateClone = Fake_WinPacketRawAllocateClone_Impl;

    Fake_WinPacketRawAllocateClone_SetupMock(2);

    PVR_PACKET_WRAPPER pkt = test_calloc(1, sizeof(*pkt));
    pkt->WinPacket = Fake_WinPacketAllocate();
    struct vr_packet *vrPkt = &pkt->VrPacket;

    struct vr_packet *clonedVrPkt = win_pclone(vrPkt);
    assert_null(clonedVrPkt);

    Fake_WinPacketRawAllocateClone_VerifyCalledCount(2);
    assert_true(WinPacketRawGetChildCountOf(pkt->WinPacket) == 0);

    Fake_WinPacketFree(pkt->WinPacket);
    test_free(pkt);

    WinPacketRawAllocateClone = Saved_WinPacketRawAllocateClone;
}

void
Test_win_pclone_ReturnsNullWhenWrapperAllocationFails(void **state)
{
    assert_true(false);
    // Saved_WinPacketRawAllocateClone = WinPacketRawAllocateClone;
    // WinPacketRawAllocateClone = Fake_WinPacketRawAllocateClone_Impl;

    // Fake_WinPacketRawAllocateClone_SetupMock(3);

    // PVR_PACKET_WRAPPER pkt = test_calloc(1, sizeof(*pkt));
    // pkt->WinPacket = Fake_WinPacketAllocate();
    // struct vr_packet *vrPkt = &pkt->VrPacket;

    // struct vr_packet *clonedVrPkt = win_pclone(vrPkt);
    // assert_null(clonedVrPkt);

    // Fake_WinPacketRawAllocateClone_VerifyCalledCount(2);
    // assert_true(WinPacketRawGetChildCountOf(pkt->WinPacket) == 0);

    // Fake_WinPacketFree(pkt->WinPacket);
    // test_free(pkt);

    // WinPacketRawAllocateClone = Saved_WinPacketRawAllocateClone;
}
