#ifndef TESTING_SIZE
#error
#endif

#include "test_defines.h"

#ifdef TESTING_FETCH_AND_X
#define TESTING_FUNCTION     EVAL3(vr_sync_fetch_and_and_, TESTING_SIZE, u)
#else
#define TESTING_FUNCTION     EVAL3(vr_sync_and_and_fetch_, TESTING_SIZE, u)
#endif
#define TESTING_TYPE         EVAL2(UINT, TESTING_SIZE)
#define TESTING_MAX          EVAL3(UINT, TESTING_SIZE, _MAX)
#define TEST_NAME(S)        EVAL2(TESTING_FUNCTION, S)

#ifdef TESTING_FETCH_AND_X
#define GENERATE_TEST_CASE(A, B, C)     GENERATE_TEST_CASE_FETCH_AND_X(A, B, C)
#else
#define GENERATE_TEST_CASE(A, B, C)     GENERATE_TEST_CASE_X_AND_FETCH(A, B, C)
#endif

// basic test, makes sure the operations are in correct order (operation and return or the other way)
static void TEST_NAME(_basic) (void **state) {
    UNREFERENCED_PARAMETER(state);
    GENERATE_TEST_CASE(0b1010, 0b1100, 0b1000);
}

// tests if casting inside TESTING function doesn't break on maximum input and minimum output
static void TEST_NAME(_max_input) (void **state) {
    UNREFERENCED_PARAMETER(state);
    GENERATE_TEST_CASE(TESTING_MAX, 0, 0);
}

// tests if casting inside TESTING function doesn't break on maximum input and output
static void TEST_NAME(_max_output) (void **state) {
    UNREFERENCED_PARAMETER(state);
    GENERATE_TEST_CASE(TESTING_MAX, TESTING_MAX, TESTING_MAX);
}


#undef GENERATE_TEST_CASE

#undef TESTING_FUNCTION
#undef TESTING_TYPE
#undef TESTING_MAX
#undef TEST_NAME
