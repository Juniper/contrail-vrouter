/*
 * windows_builtins.h -- implementation of GCC atomic builtin functions
 *                       under MSVC
 *
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __WINDOWS_BUILTINS_H__
#define __WINDOWS_BUILTINS_H__

#include <intrin.h>

#pragma intrinsic(_InterlockedExchangeAdd16)
#pragma intrinsic(_InterlockedCompareExchange8)
#pragma intrinsic(_InterlockedCompareExchange16)
#pragma intrinsic(_InterlockedCompareExchange)
#pragma intrinsic(_InterlockedCompareExchangePointer)
#pragma intrinsic(_ReadWriteBarrier)
#pragma intrinsic(_BitScanForward)


__forceinline UINT16
vr_sync_sub_and_fetch_16u(volatile UINT16 *ptr, UINT16 val)
{
    UINT16 result = _InterlockedExchangeAdd16(
        (volatile SHORT *)ptr, -((SHORT)val));
    return result - val;
}

__forceinline UINT32
vr_sync_sub_and_fetch_32u(volatile UINT32 *ptr, UINT32 val)
{
    return InterlockedAdd((volatile LONG *)ptr, -((LONG)val));
}

__forceinline INT32
vr_sync_sub_and_fetch_32s(volatile INT32 *ptr, INT32 val)
{
    return InterlockedAdd((volatile LONG *)ptr, -((LONG)val));
}

__forceinline UINT64
vr_sync_sub_and_fetch_64u(volatile UINT64 *ptr, UINT64 val)
{
    return InterlockedAdd64((volatile LONGLONG *)ptr, -((LONGLONG)val));
}

__forceinline INT64
vr_sync_sub_and_fetch_64s(volatile INT64 *ptr, INT64 val)
{
    return InterlockedAdd64((volatile LONGLONG *)ptr, -((LONGLONG)val));
}


__forceinline UINT16
vr_sync_add_and_fetch_16u(volatile UINT16 *ptr, UINT16 val)
{
    return _InterlockedExchangeAdd16((volatile SHORT *)ptr, (SHORT)val) + val;
}

__forceinline UINT32
vr_sync_add_and_fetch_32u(volatile UINT32 *ptr, UINT32 val)
{
    return InterlockedAdd((volatile LONG *)ptr, (LONG)val);
}

__forceinline UINT64
vr_sync_add_and_fetch_64u(volatile UINT64 *ptr, UINT64 val)
{
    return InterlockedExchangeAdd64(
        (volatile LONGLONG *)ptr, (LONGLONG)val) + val;
}


__forceinline UINT32
vr_sync_fetch_and_add_32u(volatile UINT32 *ptr, UINT32 val)
{
    return InterlockedExchangeAdd((volatile LONG *)ptr, (LONG)val);
}

__forceinline UINT64
vr_sync_fetch_and_add_64u(volatile UINT64 *ptr, UINT64 val)
{
    return InterlockedExchangeAdd64((volatile LONGLONG *)ptr, (LONGLONG)val);
}


__forceinline UINT16
vr_sync_fetch_and_or_16u(volatile UINT16 *ptr, UINT16 val)
{
    return InterlockedOr16((volatile SHORT *)ptr, (SHORT)val);
}


__forceinline UINT16
vr_sync_and_and_fetch_16u(volatile UINT16 *ptr, UINT16 val)
{
    return InterlockedAnd16((volatile SHORT *)ptr, (SHORT)val) & ((SHORT)val);
}

__forceinline UINT32
vr_sync_and_and_fetch_32u(volatile UINT32 *ptr, UINT32 val)
{
    return InterlockedAnd((volatile LONG *)ptr, (LONG)val) & ((LONG)val);
}


__forceinline bool
vr_sync_bool_compare_and_swap_8s(
    volatile UINT8 *ptr, UINT8 oldval, UINT8 newval)
{
    CHAR result = _InterlockedCompareExchange8(
        (volatile CHAR *)ptr, newval, oldval);
    return result == (CHAR)oldval;
}

__forceinline bool
vr_sync_bool_compare_and_swap_8u(
    volatile UINT8 *ptr, UINT8 oldval, UINT8 newval)
{
    CHAR result = _InterlockedCompareExchange8(
        (volatile CHAR *)ptr, (CHAR)newval, (CHAR)oldval);
    return result == (CHAR)oldval;
}

__forceinline bool
vr_sync_bool_compare_and_swap_16u(
    volatile UINT16 *ptr, UINT16 oldval, UINT16 newval)
{
    SHORT result = _InterlockedCompareExchange16(
        (volatile SHORT *)ptr, (SHORT)newval, (SHORT)oldval);
    return result == (SHORT)oldval;
}

__forceinline bool
vr_sync_bool_compare_and_swap_32u(
    volatile UINT32 *ptr, UINT32 oldval, UINT32 newval)
{
    LONG result = _InterlockedCompareExchange(
        (volatile LONG *)ptr, (LONG)newval, (LONG)oldval);
    return result == (LONG)oldval;
}

__forceinline bool
vr_sync_bool_compare_and_swap_p(
    void * volatile *ptr, void *oldval, void *newval)
{
    return _InterlockedCompareExchangePointer(ptr, newval, oldval) == oldval;
}


__forceinline UINT16
vr_sync_val_compare_and_swap_16u(
    volatile UINT16 *ptr, UINT16 oldval, UINT16 newval)
{
    return _InterlockedCompareExchange16(
        (volatile SHORT *)ptr, newval, oldval);
}

__forceinline UINT8
vr_sync_lock_test_and_set_8u(volatile UINT8 *ptr, UINT8 val)
{
    return InterlockedExchange8((volatile CHAR *)ptr, val);
}

__forceinline PVOID
vr_sync_lock_test_and_set_p(volatile PVOID *ptr, PVOID val)
{
    return InterlockedExchangePointer(ptr, val);
}

__forceinline void
vr_sync_synchronize()
{
    _ReadWriteBarrier();    // compiler memory barrier (compiler level fence)
    MemoryBarrier();        // cpu memory barrier (hardware level fence)
}


__forceinline int
vr_ffs_32(int x)
{
    ULONG index, mask = (ULONG)x;
    UCHAR isNonzero = _BitScanForward(&index, mask);
    if (isNonzero) {
        return index + 1;
    } else {
        return 0;
    }
}

#endif /* __WINDOWS_BUILTINS_H__ */
