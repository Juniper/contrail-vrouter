/*
 * test_win_tx_postprocess.c
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include <vr_packet.h>
#include <win_packet.h>
#include <win_packet_raw.h>
#include <win_tx_postprocess.h>

static int
Test_win_tx_pp_SetUp(void **state)
{
    return 0;
}

static int
Test_win_tx_pp_TearDown(void **state)
{
    return 0;
}

static void
Test_win_tx_pp_ArpPacket(void **state)
{
    PVR_PACKET_WRAPPER wrapper = test_calloc(1, sizeof(*wrapper));

    struct vr_packet *packet = &wrapper->VrPacket;
    packet->vp_type = VP_TYPE_ARP;

    PWIN_PACKET_RAW expected = NULL;
    PWIN_PACKET_RAW result = WinTxPostprocess(packet);
    assert_ptr_equal(result, expected);

    test_free(wrapper);
}

#define win_tx_pp_(p, f) cmocka_unit_test_setup_teardown(p##f, p##SetUp, p##TearDown)
#define win_tx_pp(f) win_tx_pp_(Test_win_tx_pp_, f)

int main(void) {
    const struct CMUnitTest tests[] = {
        win_tx_pp(ArpPacket),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
