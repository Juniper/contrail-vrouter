/*
 * vr_stats.h
 *
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_STATS_H__
#define __VR_STATS_H__

#ifdef __cplusplus
extern "C" {
#endif

extern void vr_malloc_stats(unsigned int, unsigned int);
extern void vr_free_stats(unsigned int);

#ifdef __cplusplus
}
#endif

#endif /* __VR_STATS_H__ */