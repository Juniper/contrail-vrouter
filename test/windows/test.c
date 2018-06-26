/*
 * test.c -- test runner
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

void Test_WinPacketClone_ReturnsNullWhenCloneFails(void **state);
void Test_WinPacketClone_ReturnsPacketWhenCloneSucceeds(void **state);
void Test_WinPacketClone_RefCountIsValidAfterMultipleClones(void **state);
void Test_WinPacketClone_RefCountIsValidAfterCloneOfClone(void **state);
int Test_WinPacketClone_SetUp(void **state);
int Test_WinPacketClone_TearDown(void **state);

#define WinPacketClone_UnitTest_(p, f) cmocka_unit_test_setup_teardown(p##f, p##SetUp, p##TearDown)
#define WinPacketClone_UnitTest(f) WinPacketClone_UnitTest_(Test_WinPacketClone_, f)

int main(void) {
    const struct CMUnitTest tests[] = {
        WinPacketClone_UnitTest(ReturnsNullWhenCloneFails),
        WinPacketClone_UnitTest(ReturnsPacketWhenCloneSucceeds),
        WinPacketClone_UnitTest(RefCountIsValidAfterMultipleClones),
        WinPacketClone_UnitTest(RefCountIsValidAfterCloneOfClone),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
