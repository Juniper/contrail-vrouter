#ifndef TESTING_FUNCTION
#ifndef TESTING_OFFSET
#error
#endif
#endif

#include "test_defines.h"

extern DWORD timeout;

#define TEST_NAME(S)        EVAL2(TESTING_FUNCTION, S)
#define TEST_ARR            TEST_NAME(_arr)
#define TEST_VAR            TEST_NAME(_var)
#define TEST_EXPECT         TEST_NAME(_expect)
#define TEST_THREAD         TEST_NAME(_thread)

bool TEST_ARR[ITERATIONS * NR_THREADS];

DWORD WINAPI TEST_THREAD(void* data) {
    UNREFERENCED_PARAMETER(data);

    UINT32 i;
    for (i = 0; i < ITERATIONS; ++i)
        TEST_ARR[TESTING_FUNCTION(&TEST_VAR, 1) - TESTING_OFFSET] = TRUE;

    return 0;
}

void TEST_NAME(_races) (void **state) {
    UNREFERENCED_PARAMETER(state);

    UINT32 i;

    HANDLE threads[NR_THREADS];
    for (i = 0; i < NR_THREADS; ++i) {
        threads[i] = CreateThread(NULL, 0, TEST_THREAD, NULL, 0, NULL);
        assert_non_null(threads[i]);
    }

    DWORD ret = WaitForMultipleObjects(NR_THREADS, threads, TRUE, timeout);

    for (i = 0; i < NR_THREADS; ++i)
        CloseHandle(threads[i]);

    assert_false(ret == WAIT_TIMEOUT || ret == WAIT_FAILED);
    assert_true(TEST_VAR == TEST_EXPECT);
    for (i = 0; i < ITERATIONS * NR_THREADS; ++i)
        assert_true(TEST_ARR[i]);
}


#undef TEST_NAME
#undef TEST_ARR
#undef TEST_VAR
#undef TEST_EXPECT
#undef TEST_THREAD
