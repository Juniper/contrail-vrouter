#ifndef TESTING_SIZE
#error
#endif

#include "test_defines.h"

#ifdef TESTING_FETCH_AND_X
#define TESTING_FUNCTION     EVAL3(vr_sync_fetch_and_sub_, TESTING_SIZE, s)
#else
#define TESTING_FUNCTION     EVAL3(vr_sync_sub_and_fetch_, TESTING_SIZE, s)
#endif
#define TESTING_TYPE         EVAL2(INT, TESTING_SIZE)
#define TESTING_MIN          EVAL3(INT, TESTING_SIZE, _MIN)
#define TESTING_MAX          EVAL3(INT, TESTING_SIZE, _MAX)
#define TEST_NAME(S)        EVAL2(TESTING_FUNCTION, S)

#ifdef TESTING_FETCH_AND_X
#define GENERATE_TEST_CASE(A, B, C)     GENERATE_TEST_CASE_FETCH_AND_X(A, B, C)
#else
#define GENERATE_TEST_CASE(A, B, C)     GENERATE_TEST_CASE_X_AND_FETCH(A, B, C)
#endif

// basic tests, checks if operations on negative values work ok
static void TEST_NAME(_basic) (void **state) {
    UNREFERENCED_PARAMETER(state);
    GENERATE_TEST_CASE(-5, 2, -7);
}

// from MAXINT to MININT
static void TEST_NAME(_min) (void **state) {
    UNREFERENCED_PARAMETER(state);
    GENERATE_TEST_CASE(-1, TESTING_MAX, TESTING_MIN);
}

// from MININT to MAXINT
static void TEST_NAME(_max) (void **state) {
    UNREFERENCED_PARAMETER(state);
    GENERATE_TEST_CASE(0, -TESTING_MAX, TESTING_MAX);
}

// negate overflow
static void TEST_NAME(_negateflow) (void **state) {
    UNREFERENCED_PARAMETER(state);
    GENERATE_TEST_CASE(-1, TESTING_MIN, TESTING_MAX);
}

#undef GENERATE_TEST_CASE

#undef TESTING_FUNCTION
#undef TESTING_TYPE
#undef TESTING_MIN
#undef TESTING_MAX
#undef TEST_NAME
