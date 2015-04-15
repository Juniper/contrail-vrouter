/*
 * vr_dpdk_cksum.h - header for computing checksums in packets.
 *
 *
 * Copyright (C) 2014 Semihalf.
 */

/*
 * TODO: Following functions have been ported from DPDK 1.8.0, as they are not
 * present in DPDK 1.7.0. This file should be removed after we move to the
 * current DPDK version.
 *
 * Based on functions from dpdk/lib/librte_net/rte_ip.h.
 * 
*/

#ifndef __VR_DPDK_CKSUM_H__
#define __VR_DPDK_CKSUM_H__

inline uint32_t __rte_raw_cksum(const void *buf, size_t len, uint32_t sum);
inline uint16_t __rte_raw_cksum_reduce(uint32_t sum);
inline uint16_t rte_raw_cksum(const void *buf, size_t len);
inline uint16_t rte_ipv4_phdr_cksum(const struct vr_ip *ipv4_hdr,
                                        uint64_t ol_flags);
inline uint16_t rte_ipv4_udptcp_cksum(const struct vr_ip *ipv4_hdr,
                                        const void *l4_hdr);

#endif /* __VR_DPDK_CKSUM_H__ */
