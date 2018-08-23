#include "test_defines.h"

UINT32 vr_sync_fetch_and_add_32u_var = 0;
UINT32 vr_sync_fetch_and_add_32u_expect = ITERATIONS * NR_THREADS;

#define TESTING_FUNCTION     vr_sync_fetch_and_add_32u
#define TESTING_OFFSET       0
#include "algebraic_races.h"
#undef TESTING_OFFSET
#undef TESTING_FUNCTION


UINT64 vr_sync_fetch_and_add_64u_var = 0;
UINT64 vr_sync_fetch_and_add_64u_expect = ITERATIONS * NR_THREADS;

#define TESTING_FUNCTION     vr_sync_fetch_and_add_64u
#define TESTING_OFFSET       0
#include "algebraic_races.h"
#undef TESTING_OFFSET
#undef TESTING_FUNCTION


UINT32 vr_sync_add_and_fetch_32u_var = 0;
UINT32 vr_sync_add_and_fetch_32u_expect = ITERATIONS * NR_THREADS;

#define TESTING_FUNCTION     vr_sync_add_and_fetch_32u
#define TESTING_OFFSET       1
#include "algebraic_races.h"
#undef TESTING_OFFSET
#undef TESTING_FUNCTION


UINT32 vr_sync_sub_and_fetch_32u_var = ITERATIONS * NR_THREADS;
UINT32 vr_sync_sub_and_fetch_32u_expect = 0;

#define TESTING_FUNCTION     vr_sync_sub_and_fetch_32u
#define TESTING_OFFSET       0
#include "algebraic_races.h"
#undef TESTING_OFFSET
#undef TESTING_FUNCTION


UINT32 vr_sync_sub_and_fetch_32s_var = ITERATIONS * NR_THREADS;
UINT32 vr_sync_sub_and_fetch_32s_expect = 0;

#define TESTING_FUNCTION     vr_sync_sub_and_fetch_32s
#define TESTING_OFFSET       0
#include "algebraic_races.h"
#undef TESTING_OFFSET
#undef TESTING_FUNCTION


UINT64 vr_sync_sub_and_fetch_64u_var = ITERATIONS * NR_THREADS;
UINT64 vr_sync_sub_and_fetch_64u_expect = 0;

#define TESTING_FUNCTION     vr_sync_sub_and_fetch_64u
#define TESTING_OFFSET       0
#include "algebraic_races.h"
#undef TESTING_OFFSET
#undef TESTING_FUNCTION


UINT64 vr_sync_sub_and_fetch_64s_var = ITERATIONS * NR_THREADS;
UINT64 vr_sync_sub_and_fetch_64s_expect = 0;

#define TESTING_FUNCTION     vr_sync_sub_and_fetch_64s
#define TESTING_OFFSET       0
#include "algebraic_races.h"
#undef TESTING_OFFSET
#undef TESTING_FUNCTION
