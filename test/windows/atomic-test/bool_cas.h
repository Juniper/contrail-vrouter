#ifndef TESTING_TYPE
#ifndef TESTING_FUNCTION
#error
#endif
#endif

#include "test_defines.h"

#define TESTING_MAX         EVAL2(TESTING_TYPE, _MAX)
#define TEST_NAME(S)        EVAL2(TESTING_FUNCTION, S)

#define GENERATE_TEST_CASE_BOOL_CAS(A, B, C)        TESTING_TYPE a = (TESTING_TYPE)(A), b = (TESTING_TYPE)(B);              \
                                                    TESTING_TYPE c = (TESTING_TYPE)(C), old_a = a;                          \
                                                    bool ret = TESTING_FUNCTION(&a, b, c);                                  \
                                                    if(old_a == b) { /* swap inside CAS should have happened */             \
                                                        assert_true(ret);                                                   \
                                                        assert_true(a == c);                                                \
                                                    } else { /* swap inside CAS should not have happened */                 \
                                                        assert_false(ret);                                                  \
                                                        assert_true(a == old_a);                                            \
                                                    }


static void TEST_NAME(_swap) (void **state) {
    UNREFERENCED_PARAMETER(state);
    GENERATE_TEST_CASE_BOOL_CAS(5, 5, 7);
}

static void TEST_NAME(_noswap) (void **state) {
    UNREFERENCED_PARAMETER(state);
    GENERATE_TEST_CASE_BOOL_CAS(5, 9, 7);
}

static void TEST_NAME(_comp_max) (void **state) {
    UNREFERENCED_PARAMETER(state);
    GENERATE_TEST_CASE_BOOL_CAS(TESTING_MAX, TESTING_MAX, 0);
}

static void TEST_NAME(_assign_max) (void **state) {
    UNREFERENCED_PARAMETER(state);
    GENERATE_TEST_CASE_BOOL_CAS(0, 0, TESTING_MAX);
}

#undef GENERATE_TEST_CASE_BOOL_CAS
#undef TEST_NAME
#undef TESTING_MAX
