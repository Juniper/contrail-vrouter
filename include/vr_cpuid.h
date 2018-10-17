/*
 * Copyright(c) 2018 Intel Corporation
 */

#ifndef __VR_CPUID_H__
#define __VR_CPUID_H__

#include "vr_os.h"

struct vr_cpu_type_t {
    uint8_t has_sse;
    uint8_t has_sse2;
    uint8_t has_sse3;
    uint8_t has_ssse3;
    uint8_t has_sse41;
    uint8_t has_sse42;
    uint8_t has_popcnt;
    uint8_t has_rtm;
    uint8_t has_avx;
    uint8_t has_avx2;
    uint8_t has_avx512f;
};

extern void (*vr_init_cpuid)(struct vr_cpu_type_t *vr_cpu_type);
extern struct vr_cpu_type_t vr_cpu_type;

#endif /* __VR_CPUID_H__ */
