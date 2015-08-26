/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   Copyright 2014 6WIND S.A.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/* TEMPORARY HEADER FILE for DPDK version 2.1.x */

#ifndef _CUST_RTE_MBUF_H_
#define _CUST_RTE_MBUF_H_

/**
 * @file
 * RTE Mbuf
 *
 * The mbuf library provides the ability to create and destroy buffers
 * that may be used by the RTE application to store message
 * buffers. The message buffers are stored in a mempool, using the
 * RTE mempool library.
 *
 * This library provide an API to allocate/free packet mbufs, which are
 * used to carry network packets.
 *
 * To understand the concepts of packet buffers or mbufs, you
 * should read "TCP/IP Illustrated, Volume 2: The Implementation,
 * Addison-Wesley, 1995, ISBN 0-201-63354-X from Richard Stevens"
 * http://www.kohala.com/start/tcpipiv2.html
 */
/*
#include <stdint.h>
#include <rte_common.h>
#include <rte_mempool.h>
#include <rte_memory.h>
#include <rte_atomic.h>
#include <rte_prefetch.h>
#include <rte_branch_prediction.h>

#ifdef __cplusplus
extern "C" {
#endif
*/
/* deprecated options */
//#pragma GCC poison RTE_MBUF_SCATTER_GATHER
//#pragma GCC poison RTE_MBUF_REFCNT

/*
 * Packet Offload Features Flags. It also carry packet type information.
 * Critical resources. Both rx/tx shared these bits. Be cautious on any change
 *
 * - RX flags start at bit position zero, and get added to the left of previous
 *   flags.
 * - The most-significant 3 bits are reserved for generic mbuf flags
 * - TX flags therefore start at bit position 60 (i.e. 63-3), and new flags get
 *   added to the right of the previously defined flags i.e. they should count
 *   downwards, not upwards.
 *
 * Keep these flags synchronized with rte_get_rx_ol_flag_name() and
 * rte_get_tx_ol_flag_name().
 */
#define PKT_RX_VLAN_PKT      (1ULL << 0)  /**< RX packet is a 802.1q VLAN packet. */
#define PKT_RX_RSS_HASH      (1ULL << 1)  /**< RX packet with RSS hash result. */
#define PKT_RX_FDIR          (1ULL << 2)  /**< RX packet with FDIR match indicate. */
#define PKT_RX_L4_CKSUM_BAD  (1ULL << 3)  /**< L4 cksum of RX pkt. is not OK. */
#define PKT_RX_IP_CKSUM_BAD  (1ULL << 4)  /**< IP cksum of RX pkt. is not OK. */
#define PKT_RX_EIP_CKSUM_BAD (0ULL << 0)  /**< External IP header checksum error. */
#define PKT_RX_OVERSIZE      (0ULL << 0)  /**< Num of desc of an RX pkt oversize. */
#define PKT_RX_HBUF_OVERFLOW (0ULL << 0)  /**< Header buffer overflow. */
#define PKT_RX_RECIP_ERR     (0ULL << 0)  /**< Hardware processing error. */
#define PKT_RX_MAC_ERR       (0ULL << 0)  /**< MAC error. */
// #ifndef RTE_NEXT_ABI
//#define PKT_RX_IPV4_HDR      (1ULL << 5)  /**< RX packet with IPv4 header. */
//#define PKT_RX_IPV4_HDR_EXT  (1ULL << 6)  /**< RX packet with extended IPv4 header. */
//#define PKT_RX_IPV6_HDR      (1ULL << 7)  /**< RX packet with IPv6 header. */
//#define PKT_RX_IPV6_HDR_EXT  (1ULL << 8)  /**< RX packet with extended IPv6 header. */
//#endif * RTE_NEXT_ABI */

#define PKT_RX_IEEE1588_PTP  (1ULL << 9)  /**< RX IEEE1588 L2 Ethernet PT Packet. */
#define PKT_RX_IEEE1588_TMST (1ULL << 10) /**< RX IEEE1588 L2/L4 timestamped packet.*/
//#ifndef RTE_NEXT_ABI
//#define PKT_RX_TUNNEL_IPV4_HDR (1ULL << 11) /**< RX tunnel packet with IPv4 header.*/
//#define PKT_RX_TUNNEL_IPV6_HDR (1ULL << 12) /**< RX tunnel packet with IPv6 header. */
//#endif /* RTE_NEXT_ABI */
#define PKT_RX_FDIR_ID       (1ULL << 13) /**< FD id reported if FDIR match. */
#define PKT_RX_FDIR_FLX      (1ULL << 14) /**< Flexible bytes reported if FDIR match. */
#define PKT_RX_QINQ_PKT      (1ULL << 15)  /**< RX packet with double VLAN stripped. */
/* add new RX flags here */

/* add new TX flags here */

/**
 * Second VLAN insertion (QinQ) flag.
 */
#define PKT_TX_QINQ_PKT    (1ULL << 49)   /**< TX packet with double VLAN inserted. */

/**
 * TCP segmentation offload. To enable this offload feature for a
 * packet to be transmitted on hardware supporting TSO:
 *  - set the PKT_TX_TCP_SEG flag in mbuf->ol_flags (this flag implies
 *    PKT_TX_TCP_CKSUM)
 *  - set the flag PKT_TX_IPV4 or PKT_TX_IPV6
 *  - if it's IPv4, set the PKT_TX_IP_CKSUM flag and write the IP checksum
 *    to 0 in the packet
 *  - fill the mbuf offload information: l2_len, l3_len, l4_len, tso_segsz
 *  - calculate the pseudo header checksum without taking ip_len in account,
 *    and set it in the TCP header. Refer to rte_ipv4_phdr_cksum() and
 *    rte_ipv6_phdr_cksum() that can be used as helpers.
 */
#define PKT_TX_TCP_SEG       (1ULL << 50)

#define PKT_TX_IEEE1588_TMST (1ULL << 51) /**< TX IEEE1588 packet to timestamp. */

/**
 * Bits 52+53 used for L4 packet type with checksum enabled: 00: Reserved,
 * 01: TCP checksum, 10: SCTP checksum, 11: UDP checksum. To use hardware
 * L4 checksum offload, the user needs to:
 *  - fill l2_len and l3_len in mbuf
 *  - set the flags PKT_TX_TCP_CKSUM, PKT_TX_SCTP_CKSUM or PKT_TX_UDP_CKSUM
 *  - set the flag PKT_TX_IPV4 or PKT_TX_IPV6
 *  - calculate the pseudo header checksum and set it in the L4 header (only
 *    for TCP or UDP). See rte_ipv4_phdr_cksum() and rte_ipv6_phdr_cksum().
 *    For SCTP, set the crc field to 0.
 */
#define PKT_TX_L4_NO_CKSUM   (0ULL << 52) /**< Disable L4 cksum of TX pkt. */
#define PKT_TX_TCP_CKSUM     (1ULL << 52) /**< TCP cksum of TX pkt. computed by NIC. */
#define PKT_TX_SCTP_CKSUM    (2ULL << 52) /**< SCTP cksum of TX pkt. computed by NIC. */
#define PKT_TX_UDP_CKSUM     (3ULL << 52) /**< UDP cksum of TX pkt. computed by NIC. */
#define PKT_TX_L4_MASK       (3ULL << 52) /**< Mask for L4 cksum offload request. */

/**
 * Offload the IP checksum in the hardware. The flag PKT_TX_IPV4 should
 * also be set by the application, although a PMD will only check
 * PKT_TX_IP_CKSUM.
 *  - set the IP checksum field in the packet to 0
 *  - fill the mbuf offload information: l2_len, l3_len
 */
#define PKT_TX_IP_CKSUM      (1ULL << 54)

/**
 * Packet is IPv4. This flag must be set when using any offload feature
 * (TSO, L3 or L4 checksum) to tell the NIC that the packet is an IPv4
 * packet. If the packet is a tunneled packet, this flag is related to
 * the inner headers.
 */
#define PKT_TX_IPV4          (1ULL << 55)

/**
 * Packet is IPv6. This flag must be set when using an offload feature
 * (TSO or L4 checksum) to tell the NIC that the packet is an IPv6
 * packet. If the packet is a tunneled packet, this flag is related to
 * the inner headers.
 */
#define PKT_TX_IPV6          (1ULL << 56)

#define PKT_TX_VLAN_PKT      (1ULL << 57) /**< TX packet is a 802.1q VLAN packet. */

/**
 * Offload the IP checksum of an external header in the hardware. The
 * flag PKT_TX_OUTER_IPV4 should also be set by the application, alto ugh
 * a PMD will only check PKT_TX_IP_CKSUM.  The IP checksum field in the
 * packet must be set to 0.
 *  - set the outer IP checksum field in the packet to 0
 *  - fill the mbuf offload information: outer_l2_len, outer_l3_len
 */
#define PKT_TX_OUTER_IP_CKSUM   (1ULL << 58)

/**
 * Packet outer header is IPv4. This flag must be set when using any
 * outer offload feature (L3 or L4 checksum) to tell the NIC that the
 * outer header of the tunneled packet is an IPv4 packet.
 */
#define PKT_TX_OUTER_IPV4   (1ULL << 59)

/**
 * Packet outer header is IPv6. This flag must be set when using any
 * outer offload feature (L4 checksum) to tell the NIC that the outer
 * header of the tunneled packet is an IPv6 packet.
 */
#define PKT_TX_OUTER_IPV6    (1ULL << 60)

#define __RESERVED           (1ULL << 61) /**< reserved for future mbuf use */

#define IND_ATTACHED_MBUF    (1ULL << 62) /**< Indirect attached mbuf */

/* Use final bit of flags to indicate a control mbuf */
#define CTRL_MBUF_FLAG       (1ULL << 63) /**< Mbuf contains control data */

//#ifdef RTE_NEXT_ABI
/*
 * 32 bits are divided into several fields to mark packet types. Note that
 * each field is indexical.
 * - Bit 3:0 is for L2 types.
 * - Bit 7:4 is for L3 or outer L3 (for tunneling case) types.
 * - Bit 11:8 is for L4 or outer L4 (for tunneling case) types.
 * - Bit 15:12 is for tunnel types.
 * - Bit 19:16 is for inner L2 types.
 * - Bit 23:20 is for inner L3 types.
 * - Bit 27:24 is for inner L4 types.
 * - Bit 31:28 is reserved.
 *
 * To be compatible with Vector PMD, RTE_PTYPE_L3_IPV4, RTE_PTYPE_L3_IPV4_EXT,
 * RTE_PTYPE_L3_IPV6, RTE_PTYPE_L3_IPV6_EXT, RTE_PTYPE_L4_TCP, RTE_PTYPE_L4_UDP
 * and RTE_PTYPE_L4_SCTP should be kept as below in a contiguous 7 bits.
 *
 * Note that L3 types values are selected for checking IPV4/IPV6 header from
 * performance point of view. Reading annotations of RTE_ETH_IS_IPV4_HDR and
 * RTE_ETH_IS_IPV6_HDR is needed for any future changes of L3 type values.
 *
 * Note that the packet types of the same packet recognized by different
 * hardware may be different, as different hardware may have different
 * capability of packet type recognition.
 *
 * examples:
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'=0x29
 * | 'version'=6, 'next header'=0x3A
 * | 'ICMPv6 header'>
 * will be recognized on i40e hardware as packet type combination of,
 * RTE_PTYPE_L2_ETHER |
 * RTE_PTYPE_L3_IPV4_EXT_UNKNOWN |
 * RTE_PTYPE_TUNNEL_IP |
 * RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
 * RTE_PTYPE_INNER_L4_ICMP.
 *
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=0x2F
 * | 'GRE header'
 * | 'version'=6, 'next header'=0x11
 * | 'UDP header'>
 * will be recognized on i40e hardware as packet type combination of,
 * RTE_PTYPE_L2_ETHER |
 * RTE_PTYPE_L3_IPV6_EXT_UNKNOWN |
 * RTE_PTYPE_TUNNEL_GRENAT |
 * RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN |
 * RTE_PTYPE_INNER_L4_UDP.
 */
#define RTE_PTYPE_UNKNOWN                   0x00000000
/**
 * Ethernet packet type.
 * It is used for outer packet for tunneling cases.
 *
 * Packet format:
 * <'ether type'=[0x0800|0x86DD]>
 */
#define RTE_PTYPE_L2_ETHER                  0x00000001
/**
 * Ethernet packet type for time sync.
 *
 * Packet format:
 * <'ether type'=0x88F7>
 */
#define RTE_PTYPE_L2_ETHER_TIMESYNC         0x00000002
/**
 * ARP (Address Resolution Protocol) packet type.
 *
 * Packet format:
 * <'ether type'=0x0806>
 */
#define RTE_PTYPE_L2_ETHER_ARP              0x00000003
/**
 * LLDP (Link Layer Discovery Protocol) packet type.
 *
 * Packet format:
 * <'ether type'=0x88CC>
 */
#define RTE_PTYPE_L2_ETHER_LLDP             0x00000004
/**
 * Mask of layer 2 packet types.
 * It is used for outer packet for tunneling cases.
 */
#define RTE_PTYPE_L2_MASK                   0x0000000f
/**
 * IP (Internet Protocol) version 4 packet type.
 * It is used for outer packet for tunneling cases, and does not contain any
 * header option.
 *
 * Packet format:
 * <'ether type'=0x0800
 * | 'version'=4, 'ihl'=5>
 */
#define RTE_PTYPE_L3_IPV4                   0x00000010
/**
 * IP (Internet Protocol) version 4 packet type.
 * It is used for outer packet for tunneling cases, and contains header
 * options.
 *
 * Packet format:
 * <'ether type'=0x0800
 * | 'version'=4, 'ihl'=[6-15], 'options'>
 */
#define RTE_PTYPE_L3_IPV4_EXT               0x00000030
/**
 * IP (Internet Protocol) version 6 packet type.
 * It is used for outer packet for tunneling cases, and does not contain any
 * extension header.
 *
 * Packet format:
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=0x3B>
 */
#define RTE_PTYPE_L3_IPV6                   0x00000040
/**
 * IP (Internet Protocol) version 4 packet type.
 * It is used for outer packet for tunneling cases, and may or maynot contain
 * header options.
 *
 * Packet format:
 * <'ether type'=0x0800
 * | 'version'=4, 'ihl'=[5-15], <'options'>>
 */
#define RTE_PTYPE_L3_IPV4_EXT_UNKNOWN       0x00000090
/**
 * IP (Internet Protocol) version 6 packet type.
 * It is used for outer packet for tunneling cases, and contains extension
 * headers.
 *
 * Packet format:
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=[0x0|0x2B|0x2C|0x32|0x33|0x3C|0x87],
 *   'extension headers'>
 */
#define RTE_PTYPE_L3_IPV6_EXT               0x000000c0
/**
 * IP (Internet Protocol) version 6 packet type.
 * It is used for outer packet for tunneling cases, and may or maynot contain
 * extension headers.
 *
 * Packet format:
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=[0x3B|0x0|0x2B|0x2C|0x32|0x33|0x3C|0x87],
 *   <'extension headers'>>
 */
#define RTE_PTYPE_L3_IPV6_EXT_UNKNOWN       0x000000e0
/**
 * Mask of layer 3 packet types.
 * It is used for outer packet for tunneling cases.
 */
#define RTE_PTYPE_L3_MASK                   0x000000f0
/**
 * TCP (Transmission Control Protocol) packet type.
 * It is used for outer packet for tunneling cases.
 *
 * Packet format:
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'=6, 'MF'=0>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=6>
 */
#define RTE_PTYPE_L4_TCP                    0x00000100
/**
 * UDP (User Datagram Protocol) packet type.
 * It is used for outer packet for tunneling cases.
 *
 * Packet format:
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'=17, 'MF'=0>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=17>
 */
#define RTE_PTYPE_L4_UDP                    0x00000200
/**
 * Fragmented IP (Internet Protocol) packet type.
 * It is used for outer packet for tunneling cases.
 *
 * It refers to those packets of any IP types, which can be recognized as
 * fragmented. A fragmented packet cannot be recognized as any other L4 types
 * (RTE_PTYPE_L4_TCP, RTE_PTYPE_L4_UDP, RTE_PTYPE_L4_SCTP, RTE_PTYPE_L4_ICMP,
 * RTE_PTYPE_L4_NONFRAG).
 *
 * Packet format:
 * <'ether type'=0x0800
 * | 'version'=4, 'MF'=1>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=44>
 */
#define RTE_PTYPE_L4_FRAG                   0x00000300
/**
 * SCTP (Stream Control Transmission Protocol) packet type.
 * It is used for outer packet for tunneling cases.
 *
 * Packet format:
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'=132, 'MF'=0>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=132>
 */
#define RTE_PTYPE_L4_SCTP                   0x00000400
/**
 * ICMP (Internet Control Message Protocol) packet type.
 * It is used for outer packet for tunneling cases.
 *
 * Packet format:
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'=1, 'MF'=0>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=1>
 */
#define RTE_PTYPE_L4_ICMP                   0x00000500
/**
 * Non-fragmented IP (Internet Protocol) packet type.
 * It is used for outer packet for tunneling cases.
 *
 * It refers to those packets of any IP types, while cannot be recognized as
 * any of above L4 types (RTE_PTYPE_L4_TCP, RTE_PTYPE_L4_UDP,
 * RTE_PTYPE_L4_FRAG, RTE_PTYPE_L4_SCTP, RTE_PTYPE_L4_ICMP).
 *
 * Packet format:
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'!=[6|17|132|1], 'MF'=0>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'!=[6|17|44|132|1]>
 */
#define RTE_PTYPE_L4_NONFRAG                0x00000600
/**
 * Mask of layer 4 packet types.
 * It is used for outer packet for tunneling cases.
 */
#define RTE_PTYPE_L4_MASK                   0x00000f00
/**
 * IP (Internet Protocol) in IP (Internet Protocol) tunneling packet type.
 *
 * Packet format:
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'=[4|41]>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=[4|41]>
 */
#define RTE_PTYPE_TUNNEL_IP                 0x00001000
/**
 * GRE (Generic Routing Encapsulation) tunneling packet type.
 *
 * Packet format:
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'=47>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=47>
 */
#define RTE_PTYPE_TUNNEL_GRE                0x00002000
/**
 * VXLAN (Virtual eXtensible Local Area Network) tunneling packet type.
 *
 * Packet format:
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'=17
 * | 'destination port'=4798>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=17
 * | 'destination port'=4798>
 */
#define RTE_PTYPE_TUNNEL_VXLAN              0x00003000
/**
 * NVGRE (Network Virtualization using Generic Routing Encapsulation) tunneling
 * packet type.
 *
 * Packet format:
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'=47
 * | 'protocol type'=0x6558>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=47
 * | 'protocol type'=0x6558'>
 */
#define RTE_PTYPE_TUNNEL_NVGRE              0x00004000
/**
 * GENEVE (Generic Network Virtualization Encapsulation) tunneling packet type.
 *
 * Packet format:
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'=17
 * | 'destination port'=6081>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=17
 * | 'destination port'=6081>
 */
#define RTE_PTYPE_TUNNEL_GENEVE             0x00005000
/**
 * Tunneling packet type of Teredo, VXLAN (Virtual eXtensible Local Area
 * Network) or GRE (Generic Routing Encapsulation) could be recognized as this
 * packet type, if they can not be recognized independently as of hardware
 * capability.
 */
#define RTE_PTYPE_TUNNEL_GRENAT             0x00006000
/**
 * Added custom header directive - UDP tunneling
 * We need support for MPLS over UDP.
 *
 */
#define RTE_CONTRAIL_PTYPE_TUNNEL_MPLS_UDP   0x00007000
/**
 * Added custom header directive - GRE tunneling
 * We need support for MPLS over GRE.
 */
#define RTE_CONTRAIL_PTYPE_TUNNEL_MPLS_GRE    0x00008000
/**
 * Mask of tunneling packet types.
 */
#define RTE_PTYPE_TUNNEL_MASK               0x0000f000
/**
 * Ethernet packet type.
 * It is used for inner packet type only.
 *
 * Packet format (inner only):
 * <'ether type'=[0x800|0x86DD]>
 */
#define RTE_PTYPE_INNER_L2_ETHER            0x00010000
/**
 * Ethernet packet type with VLAN (Virtual Local Area Network) tag.
 *
 * Packet format (inner only):
 * <'ether type'=[0x800|0x86DD], vlan=[1-4095]>
 */
#define RTE_PTYPE_INNER_L2_ETHER_VLAN       0x00020000
/**
 * Mask of inner layer 2 packet types.
 */
#define RTE_PTYPE_INNER_L2_MASK             0x000f0000
/**
 * IP (Internet Protocol) version 4 packet type.
 * It is used for inner packet only, and does not contain any header option.
 *
 * Packet format (inner only):
 * <'ether type'=0x0800
 * | 'version'=4, 'ihl'=5>
 */
#define RTE_PTYPE_INNER_L3_IPV4             0x00100000
/**
 * IP (Internet Protocol) version 4 packet type.
 * It is used for inner packet only, and contains header options.
 *
 * Packet format (inner only):
 * <'ether type'=0x0800
 * | 'version'=4, 'ihl'=[6-15], 'options'>
 */
#define RTE_PTYPE_INNER_L3_IPV4_EXT         0x00200000
/**
 * IP (Internet Protocol) version 6 packet type.
 * It is used for inner packet only, and does not contain any extension header.
 *
 * Packet format (inner only):
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=0x3B>
 */
#define RTE_PTYPE_INNER_L3_IPV6             0x00300000
/**
 * IP (Internet Protocol) version 4 packet type.
 * It is used for inner packet only, and may or maynot contain header options.
 *
 * Packet format (inner only):
 * <'ether type'=0x0800
 * | 'version'=4, 'ihl'=[5-15], <'options'>>
 */
#define RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN 0x00400000
/**
 * IP (Internet Protocol) version 6 packet type.
 * It is used for inner packet only, and contains extension headers.
 *
 * Packet format (inner only):
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=[0x0|0x2B|0x2C|0x32|0x33|0x3C|0x87],
 *   'extension headers'>
 */
#define RTE_PTYPE_INNER_L3_IPV6_EXT         0x00500000
/**
 * IP (Internet Protocol) version 6 packet type.
 * It is used for inner packet only, and may or maynot contain extension
 * headers.
 *
 * Packet format (inner only):
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=[0x3B|0x0|0x2B|0x2C|0x32|0x33|0x3C|0x87],
 *   <'extension headers'>>
 */
#define RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN 0x00600000
/**
 * Mask of inner layer 3 packet types.
 */
#define RTE_PTYPE_INNER_L3_MASK             0x00f00000
/**
 * TCP (Transmission Control Protocol) packet type.
 * It is used for inner packet only.
 *
 * Packet format (inner only):
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'=6, 'MF'=0>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=6>
 */
#define RTE_PTYPE_INNER_L4_TCP              0x01000000
/**
 * UDP (User Datagram Protocol) packet type.
 * It is used for inner packet only.
 *
 * Packet format (inner only):
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'=17, 'MF'=0>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=17>
 */
#define RTE_PTYPE_INNER_L4_UDP              0x02000000
/**
 * Fragmented IP (Internet Protocol) packet type.
 * It is used for inner packet only, and may or maynot have layer 4 packet.
 *
 * Packet format (inner only):
 * <'ether type'=0x0800
 * | 'version'=4, 'MF'=1>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=44>
 */
#define RTE_PTYPE_INNER_L4_FRAG             0x03000000
/**
 * SCTP (Stream Control Transmission Protocol) packet type.
 * It is used for inner packet only.
 *
 * Packet format (inner only):
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'=132, 'MF'=0>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=132>
 */
#define RTE_PTYPE_INNER_L4_SCTP             0x04000000
/**
 * ICMP (Internet Control Message Protocol) packet type.
 * It is used for inner packet only.
 *
 * Packet format (inner only):
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'=1, 'MF'=0>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'=1>
 */
#define RTE_PTYPE_INNER_L4_ICMP             0x05000000
/**
 * Non-fragmented IP (Internet Protocol) packet type.
 * It is used for inner packet only, and may or maynot have other unknown layer
 * 4 packet types.
 *
 * Packet format (inner only):
 * <'ether type'=0x0800
 * | 'version'=4, 'protocol'!=[6|17|132|1], 'MF'=0>
 * or,
 * <'ether type'=0x86DD
 * | 'version'=6, 'next header'!=[6|17|44|132|1]>
 */
#define RTE_PTYPE_INNER_L4_NONFRAG          0x06000000
/**
 * Mask of inner layer 4 packet types.
 */
#define RTE_PTYPE_INNER_L4_MASK             0x0f000000

/**
 * Check if the (outer) L3 header is IPv4. To avoid comparing IPv4 types one by
 * one, bit 4 is selected to be used for IPv4 only. Then checking bit 4 can
 * determine if it is an IPV4 packet.
 */
#define  RTE_ETH_IS_IPV4_HDR(ptype) ((ptype) & RTE_PTYPE_L3_IPV4)

/**
 * Check if the (outer) L3 header is IPv4. To avoid comparing IPv4 types one by
 * one, bit 6 is selected to be used for IPv4 only. Then checking bit 6 can
 * determine if it is an IPV4 packet.
 */
#define  RTE_ETH_IS_IPV6_HDR(ptype) ((ptype) & RTE_PTYPE_L3_IPV6)

/* Check if it is a tunneling packet */
#define RTE_ETH_IS_TUNNEL_PKT(ptype) ((ptype) & (RTE_PTYPE_TUNNEL_MASK | \
                                                 RTE_PTYPE_INNER_L2_MASK | \
                                                 RTE_PTYPE_INNER_L3_MASK | \
                                                 RTE_PTYPE_INNER_L4_MASK))

typedef enum POINTER_SUM{
    L2_INNER = 0,
    L3_INNER,
    L4_INNER,
    L2_OUTER,
    L3_OUTER,
    L4_OUTER
}MBUF_PTR_SUM ;

/*
#ifdef __cplusplus
}
#endif
*/
#endif /* _CUST_RTE_MBUF_H_ */

