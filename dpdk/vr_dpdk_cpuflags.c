/*
 * Copyright(c) 2018 Intel Corporation
 */

#include "vr_types.h"
#include "vr_cpuid.h"

#include "rte_cpuflags.h"

struct vr_cpu_type_t vr_cpu_type;

void vr_dpdk_init_cpuid(struct vr_cpu_type_t *cpu)
{
    memset(cpu, 0, sizeof(struct vr_cpu_type_t));
#ifdef __VR_X86_64__
    cpu->has_sse = rte_cpu_get_flag_enabled(RTE_CPUFLAG_SSE);
    cpu->has_sse2 = rte_cpu_get_flag_enabled(RTE_CPUFLAG_SSE2);
    cpu->has_sse3 = rte_cpu_get_flag_enabled(RTE_CPUFLAG_SSE3);
    cpu->has_ssse3 = rte_cpu_get_flag_enabled(RTE_CPUFLAG_SSSE3);
    cpu->has_sse41 = rte_cpu_get_flag_enabled(RTE_CPUFLAG_SSE4_1);
    cpu->has_sse42 = rte_cpu_get_flag_enabled(RTE_CPUFLAG_SSE4_2);
    cpu->has_popcnt = rte_cpu_get_flag_enabled(RTE_CPUFLAG_POPCNT);
    cpu->has_rtm = rte_cpu_get_flag_enabled(RTE_CPUFLAG_RTM);
    cpu->has_avx = rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX);
    cpu->has_avx2 = rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX2);
    cpu->has_avx512f = rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F);
#endif
}

