#pragma once

#define TESTING_SIZE 16
#include "sub_unsigned.h"
#undef TESTING_SIZE

#define TESTING_SIZE 32
#include "sub_unsigned.h"
#undef TESTING_SIZE

#define TESTING_SIZE 64
#include "sub_unsigned.h"
#undef TESTING_SIZE


#define TESTING_SIZE 32
#include "sub_signed.h"
#undef TESTING_SIZE

#define TESTING_SIZE 64
#include "sub_signed.h"
#undef TESTING_SIZE


#define TESTING_SIZE 16
#include "add_unsigned.h"
#undef TESTING_SIZE

#define TESTING_SIZE 32
#include "add_unsigned.h"
#undef TESTING_SIZE


#define TESTING_SIZE 16
#include "and_unsigned.h"
#undef TESTING_SIZE

#define TESTING_SIZE 32
#include "and_unsigned.h"
#undef TESTING_SIZE


#define TESTING_FETCH_AND_X

#define TESTING_SIZE 32
#include "add_unsigned.h"
#undef TESTING_SIZE

#define TESTING_SIZE 64
#include "add_unsigned.h"
#undef TESTING_SIZE


#define TESTING_SIZE 16
#include "or_unsigned.h"
#undef TESTING_SIZE

#undef TESTING_FETCH_AND_X


#define TESTING_FUNCTION    vr_sync_bool_compare_and_swap_8u
#define TESTING_TYPE        UINT8
#include "bool_cas.h"
#undef TESTING_TYPE
#undef TESTING_FUNCTION

#define TESTING_FUNCTION    vr_sync_bool_compare_and_swap_16u
#define TESTING_TYPE        UINT16
#include "bool_cas.h"
#undef TESTING_TYPE
#undef TESTING_FUNCTION

#define TESTING_FUNCTION    vr_sync_bool_compare_and_swap_32u
#define TESTING_TYPE        UINT32
#include "bool_cas.h"
#undef TESTING_TYPE
#undef TESTING_FUNCTION

#define TESTING_FUNCTION    vr_sync_bool_compare_and_swap_p
#define TESTING_TYPE        PVOID
#include "bool_cas.h"
#undef TESTING_TYPE
#undef TESTING_FUNCTION
