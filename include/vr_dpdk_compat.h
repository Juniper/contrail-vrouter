/*
 * vr_dpdk_compat.h - DPDK compatibility definitions
 *
 * Copyright (c) 2015 Semihalf.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <rte_version.h>

#ifndef __VRDPDKCOMPAT_H__
#define __VRDPDKCOMPAT_H__

/*
 * DPDK 2.1
 */
#if (RTE_VERSION >= RTE_VERSION_NUM(2, 1, 0, 0))

/*
 * DPDK 2.0
 */
#elif (RTE_VERSION >= RTE_VERSION_NUM(2, 0, 0, 0))

/* Enable port statistics. */
#define RTE_PORT_STATS_COLLECT

/**
 * A macro that points to an offset into the data in the mbuf.
 *
 * The returned pointer is cast to type t. Before using this
 * function, the user must ensure that the first segment is large
 * enough to accommodate its data.
 *
 * @param m
 *   The packet mbuf.
 * @param o
 *   The offset into the mbuf data.
 * @param t
 *   The type to cast the result into.
 */
#define rte_pktmbuf_mtod_offset(m, t, o) \
        ((t)((char *)(m)->buf_addr + (m)->data_off + (o)))

#endif /* RTE_VERSION */

#endif /* __VRDPDKCOMPAT_H__ */
