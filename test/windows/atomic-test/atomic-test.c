#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>

#include "unit_tests.h"
#include "races_tests.h"

const char* timeout_env_name = "VR_ATOMIC_TEST_TIMEOUT";
const DWORD default_timeout = 120 * 1000; // 2 minutes in miliseconds (per multithreaded test)
DWORD timeout;

int main(void) {
    char* timeout_env = getenv(timeout_env_name);
    timeout = timeout_env ? atoi(timeout_env) : default_timeout;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(vr_sync_sub_and_fetch_16u_basic),
        cmocka_unit_test(vr_sync_sub_and_fetch_16u_high),
        cmocka_unit_test(vr_sync_sub_and_fetch_16u_max),
        cmocka_unit_test(vr_sync_sub_and_fetch_16u_negative),
        cmocka_unit_test(vr_sync_sub_and_fetch_16u_underflow),
        cmocka_unit_test(vr_sync_sub_and_fetch_32u_basic),
        cmocka_unit_test(vr_sync_sub_and_fetch_32u_high),
        cmocka_unit_test(vr_sync_sub_and_fetch_32u_max),
        cmocka_unit_test(vr_sync_sub_and_fetch_32u_negative),
        cmocka_unit_test(vr_sync_sub_and_fetch_32u_underflow),
        cmocka_unit_test(vr_sync_sub_and_fetch_32s_basic),
        cmocka_unit_test(vr_sync_sub_and_fetch_32s_min),
        cmocka_unit_test(vr_sync_sub_and_fetch_32s_max),
        cmocka_unit_test(vr_sync_sub_and_fetch_32s_negateflow),
        cmocka_unit_test(vr_sync_sub_and_fetch_64u_basic),
        cmocka_unit_test(vr_sync_sub_and_fetch_64u_high),
        cmocka_unit_test(vr_sync_sub_and_fetch_64u_max),
        cmocka_unit_test(vr_sync_sub_and_fetch_64u_negative),
        cmocka_unit_test(vr_sync_sub_and_fetch_64u_underflow),
        cmocka_unit_test(vr_sync_sub_and_fetch_64s_basic),
        cmocka_unit_test(vr_sync_sub_and_fetch_64s_min),
        cmocka_unit_test(vr_sync_sub_and_fetch_64s_max),
        cmocka_unit_test(vr_sync_sub_and_fetch_64s_negateflow),
        cmocka_unit_test(vr_sync_add_and_fetch_32u_basic),
        cmocka_unit_test(vr_sync_add_and_fetch_32u_max),
        cmocka_unit_test(vr_sync_add_and_fetch_32u_negative),
        cmocka_unit_test(vr_sync_add_and_fetch_32u_overflow),
        cmocka_unit_test(vr_sync_add_and_fetch_16u_basic),
        cmocka_unit_test(vr_sync_add_and_fetch_16u_max),
        cmocka_unit_test(vr_sync_add_and_fetch_16u_negative),
        cmocka_unit_test(vr_sync_add_and_fetch_16u_overflow),
        cmocka_unit_test(vr_sync_fetch_and_add_32u_basic),
        cmocka_unit_test(vr_sync_fetch_and_add_32u_max),
        cmocka_unit_test(vr_sync_fetch_and_add_32u_negative),
        cmocka_unit_test(vr_sync_fetch_and_add_32u_overflow),
        cmocka_unit_test(vr_sync_fetch_and_add_64u_basic),
        cmocka_unit_test(vr_sync_fetch_and_add_64u_max),
        cmocka_unit_test(vr_sync_fetch_and_add_64u_negative),
        cmocka_unit_test(vr_sync_fetch_and_add_64u_overflow),
        cmocka_unit_test(vr_sync_fetch_and_or_16u_basic),
        cmocka_unit_test(vr_sync_fetch_and_or_16u_max),
        cmocka_unit_test(vr_sync_and_and_fetch_16u_basic),
        cmocka_unit_test(vr_sync_and_and_fetch_16u_max_input),
        cmocka_unit_test(vr_sync_and_and_fetch_16u_max_output),
        cmocka_unit_test(vr_sync_and_and_fetch_32u_basic),
        cmocka_unit_test(vr_sync_and_and_fetch_32u_max_input),
        cmocka_unit_test(vr_sync_and_and_fetch_32u_max_output),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_8u_swap),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_8u_noswap),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_8u_comp_max),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_8u_assign_max),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_16u_swap),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_16u_noswap),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_16u_comp_max),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_16u_assign_max),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_32u_swap),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_32u_noswap),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_32u_comp_max),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_32u_assign_max),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_p_swap),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_p_noswap),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_p_comp_max),
        cmocka_unit_test(vr_sync_bool_compare_and_swap_p_assign_max),
        cmocka_unit_test(vr_sync_fetch_and_add_32u_races),
        cmocka_unit_test(vr_sync_fetch_and_add_64u_races),
        cmocka_unit_test(vr_sync_add_and_fetch_32u_races),
        cmocka_unit_test(vr_sync_sub_and_fetch_32u_races),
        cmocka_unit_test(vr_sync_sub_and_fetch_32s_races),
        cmocka_unit_test(vr_sync_sub_and_fetch_64u_races),
        cmocka_unit_test(vr_sync_sub_and_fetch_64s_races),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
