/*
 * test_win_pfree.c
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

extern void win_pfree(struct vr_packet *pkt, unsigned short reason);

void Test_win_pfree_AssertsWhenVrPacketIsNull(void** state) {
    expect_assert_failure(win_pfree(NULL, 0));
}

void Test_win_pfree_FreeSuccessful(void** state) {
    PVR_PACKET_WRAPPER pkt = test_calloc(1, sizeof(*pkt));
    pkt->WinPacket = Fake_WinPacketAllocateNonOwned();
    struct vr_packet *vrPkt = &pkt->VrPacket;

    win_pfree(vrPkt, 0);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(Test_win_pfree_AssertsWhenVrPacketIsNull),
        cmocka_unit_test(Test_win_pfree_FreeSuccessful),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
