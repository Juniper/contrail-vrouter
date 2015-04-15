/*
 * Copyright (C) 2014 Semihalf.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * vr_dpdk_cksum.c -- computing checksums in packets.
 *
 */

/*
 * TODO: Following functions have been ported from DPDK 1.8.0, as they are not
 * present in DPDK 1.7.0. This file should be removed after we move to the
 * current DPDK version.
 *
 * Based on functions from dpdk/lib/librte_net/rte_ip.h.
 * 
*/

#include <stdio.h>
#include <stdint.h>

#include "vr_dpdk.h"
#include "vr_dpdk_cksum.h"

#include <rte_byteorder.h>


/*
 * rte_raw_cksum - Calculate a sum of all words in the buffer.
 * Helper routine for the rte_raw_cksum().
 *
 * @param buf
 *   Pointer to the buffer.
 * @param len
 *   Length of the buffer.
 * @param sum
 *   Initial value of the sum.
 * @return
 *   sum += Sum of all words in the buffer.
 */
inline uint32_t
__rte_raw_cksum(const void *buf, size_t len, uint32_t sum)
{
    /* workaround gcc strict-aliasing warning */
    uintptr_t ptr = (uintptr_t)buf;
    const uint16_t *u16 = (const uint16_t *)ptr;

    while (len >= (sizeof(*u16) * 4)) {
        sum += u16[0];
        sum += u16[1];
        sum += u16[2];
        sum += u16[3];
        len -= sizeof(*u16) * 4;
        u16 += 4;
    }
    while (len >= sizeof(*u16)) {
        sum += *u16;
        len -= sizeof(*u16);
        u16 += 1;
    }

    /* if length is in odd bytes */
    if (len == 1)
        sum += *((const uint8_t *)u16);

    return sum;
}

/*
 * __rte_raw_cksum_reduce - Reduce a sum to the non-complemented checksum.
 * Helper routine for the rte_raw_cksum().
 *
 * @param sum
 *   Value of the sum.
 * @return
 *   The non-complemented checksum.
 */
inline uint16_t
__rte_raw_cksum_reduce(uint32_t sum)
{
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    return (uint16_t)sum;
}

/*
 * rte_raw_cksum - Process the non-complemented checksum of a buffer.
 *
 * @param buf
 *   Pointer to the buffer.
 * @param len
 *   Length of the buffer.
 * @return
 *   The non-complemented checksum.
 */
inline uint16_t
rte_raw_cksum(const void *buf, size_t len)
{
    uint32_t sum;

    sum = __rte_raw_cksum(buf, len, 0);
    return __rte_raw_cksum_reduce(sum);
}

/*
 * rte_ipv4_phdr_cksum - Process the pseudo-header checksum of an IPv4 header.
 *
 * The checksum field must be set to 0 by the caller.
 *
 * Depending on the ol_flags, the pseudo-header checksum expected by the
 * drivers is not the same. For instance, when TSO is enabled, the IP
 * payload length must not be included in the packet.
 *
 * When ol_flags is 0, it computes the standard pseudo-header checksum.
 *
 * @param ipv4_hdr
 *   The pointer to the contiguous IPv4 header.
 * @param ol_flags
 *   The ol_flags of the associated mbuf.
 * @return
 *   The non-complemented checksum to set in the L4 header.
 */
inline uint16_t
rte_ipv4_phdr_cksum(const struct vr_ip *ipv4_hdr, uint64_t ol_flags)
{
    struct ipv4_psd_header {
        uint32_t src_addr; /* IP address of source host. */
        uint32_t dst_addr; /* IP address of destination host. */
        uint8_t  zero;     /* zero. */
        uint8_t  proto;    /* L4 protocol type. */
        uint16_t len;      /* L4 length. */
    } psd_hdr;

    psd_hdr.src_addr = ipv4_hdr->ip_saddr;
    psd_hdr.dst_addr = ipv4_hdr->ip_daddr;
    psd_hdr.zero = 0;
    psd_hdr.proto = ipv4_hdr->ip_proto;
    /* if (ol_flags & PKT_TX_TCP_SEG) {
        psd_hdr.len = 0;
    } else {*/
        psd_hdr.len = rte_cpu_to_be_16( /* rte_byteorder.h */
            (uint16_t)(rte_be_to_cpu_16(ipv4_hdr->ip_len)
                - sizeof(struct vr_ip)));
    /*}*/
    return rte_raw_cksum(&psd_hdr, sizeof(psd_hdr));
}

/*
 * rte_ipv4_udptcp_cksum - Process the IPv4 UDP or TCP checksum.
 *
 * The IPv4 header should not contains options. The IP and layer 4
 * checksum must be set to 0 in the packet by the caller.
 *
 * @param ipv4_hdr
 *   The pointer to the contiguous IPv4 header.
 * @param l4_hdr
 *   The pointer to the beginning of the L4 header.
 * @return
 *   The complemented checksum to set in the IP packet.
 */
inline uint16_t
rte_ipv4_udptcp_cksum(const struct vr_ip *ipv4_hdr, const void *l4_hdr)
{
    uint32_t cksum;
    uint32_t l4_len;

    l4_len = rte_be_to_cpu_16(ipv4_hdr->ip_len) - /* rte_byteorder.h */
        sizeof(struct vr_ip);

    cksum = rte_raw_cksum(l4_hdr, l4_len);
    cksum += rte_ipv4_phdr_cksum(ipv4_hdr, 0);

    cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
    cksum = (~cksum) & 0xffff;
    if (cksum == 0)
        cksum = 0xffff;

    return cksum;
}
