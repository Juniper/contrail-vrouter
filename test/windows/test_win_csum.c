/*
 * test_win_csum.c
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
#include "win_packet_impl.h"
#include "fake_win_packet.h"

int
Test_win_csum_SetUp(void **state)
{
    return 0;
}

int
Test_win_csum_TearDown(void** state)
{
    return 0;
}

void
Test_win_csum_ReturnsCorrectIPCsum(void **state)
{
    // TODO
}

#define win_csum_UnitTest_(p, f) cmocka_unit_test_setup_teardown(p##f, p##SetUp, p##TearDown)
#define win_csum_UnitTest(f) win_csum_UnitTest_(Test_win_csum_, f)

int main(void) {
    const struct CMUnitTest tests[] = {
        win_csum_UnitTest(ReturnsCorrectIPCsum)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
