/*
 * Copyright (C) 2016 Juniper Networks.
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
 * vr_dpdk_gso.c -- TCP Offloads on the sender
 *
 * This is an adaptation of FreeBSD's patch for gso
 * Copyright (C) 2014, Stefano Garzarella - Universita` di Pisa
 * All rights reserved.
 * BSD LICENSE
 *
 *
 */

#include "vr_dpdk.h"
#include "vr_dpdk_netlink.h"
#include "vr_dpdk_usocket.h"
#include "vr_dpdk_virtio.h"
#include "vr_dpdk_gro.h"
#include "vr_packet.h"
#include "vr_datapath.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip_frag.h>
#include <rte_ip.h>
#include <rte_port_ethdev.h>

#if (RTE_VERSION == RTE_VERSION_NUM(2, 1, 0, 0))
#include <rte_eth_af_packet.h>
#endif

#include <rte_hash.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_tcp.h>
#include <rte_eth_bond.h>

#define TCP_CWR_FLAG 0x80
/*
 * Structure that contains the state during the TCP segmentation
 */
struct dpdk_gso_state {
   void    (*update)
       (struct rte_mbuf*, struct dpdk_gso_state*);
   void    (*internal)
       (struct rte_mbuf*, struct dpdk_gso_state*);
   union {
       struct ipv4_hdr *ip;
       struct ipv6_hdr *ip6;
   };
   struct tcp_hdr *tcp;
   int mac_hlen;
   int ip_hlen;
   int tcp_hlen;
   int hlen;
   int pay_len;
   uint32_t tcp_seq;
   uint16_t ip_id;
   uint16_t ip_off;
   int tx_cksum_offload;
};

/**
 * Process the IPv6 UDP or TCP checksum in a **chained** mbuf.
 *
 * Layer 4 checksum must be set to 0 in the packet by the caller.
 *
 * @param ipv6_hdr
 *   The pointer to the contiguous IPv4 header.
 * @param l4_hdr
 *   The pointer to the beginning of the L4 header.
 * @return
 *   The complemented checksum to set in the IP packet.
 */
inline uint16_t
dpdk_ipv6_udptcp_cksum(struct rte_mbuf *m, const struct ipv6_hdr *ipv6_hdr,
                                                                    uint8_t *l4_hdr)
{
    uint32_t cksum = 0;
    uint32_t l4_len;
    uint32_t data_len = 0, rem_len = 0;
    uint8_t *data_ptr = NULL;

    l4_len = rte_be_to_cpu_16(ipv6_hdr->payload_len);

    do {
        data_ptr = likely(!!data_ptr)? rte_pktmbuf_mtod(m, uint8_t*):l4_hdr;
        data_len = likely(!!data_len)? rte_pktmbuf_data_len(m):
                   rte_pktmbuf_mtod(m, uint8_t*) + rte_pktmbuf_data_len(m) - l4_hdr ;
        if (rem_len + data_len > l4_len)
            data_len = l4_len - rem_len;
        cksum += rte_raw_cksum(data_ptr, data_len);
        rem_len += data_len;
        m = m->next;
    } while (m && rem_len < l4_len);

    cksum += rte_ipv6_phdr_cksum(ipv6_hdr, 0);
    cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
    cksum = (~cksum) & 0xffff;
    if (cksum == 0)
        cksum = 0xffff;

    return cksum;
}

/**
 * Process the IPv4 UDP or TCP checksum in a **chained** mbuf.
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
dpdk_ipv4_udptcp_cksum(struct rte_mbuf *m,
                       const struct ipv4_hdr *ipv4_hdr,
                       uint8_t *l4_hdr)
{
    uint32_t cksum = 0;
    uint32_t l4_len;
    uint32_t data_len = 0, rem_len = 0;
    uint8_t *data_ptr = NULL;

    l4_len = rte_be_to_cpu_16(ipv4_hdr->total_length) -
        ((ipv4_hdr->version_ihl & 0xf) << 2);

    do {
        data_ptr = likely(!!data_ptr)? rte_pktmbuf_mtod(m, uint8_t*):l4_hdr;
        data_len = likely(!!data_len)? rte_pktmbuf_data_len(m):
                   rte_pktmbuf_mtod(m, uint8_t*) + rte_pktmbuf_data_len(m) - l4_hdr ;
        if (rem_len + data_len > l4_len)
            data_len = l4_len - rem_len;
        cksum += rte_raw_cksum(data_ptr, data_len);
        rem_len += data_len;
        m = m->next;
    } while (m && rem_len < l4_len);

    cksum += rte_ipv4_phdr_cksum(ipv4_hdr, 0);
    cksum = ((cksum & 0xffff0000) >> 16) + (cksum & 0xffff);
    cksum = (~cksum) & 0xffff;
    if (cksum == 0)
        cksum = 0xffff;

    return cksum;
}

/* Split chained mbuf to individual mbufs and save the pointers in pkts_out */
static int32_t
dpdk_split_chained_mbuf(struct rte_mbuf *pkt_in, struct rte_mbuf **pkts_out,
               uint16_t nb_pkts_out, uint16_t hdr_len, uint16_t frag_size)
{
    struct rte_mbuf *curr_pkt = pkt_in, *next_pkt;
    uint32_t nb_segs = 0, total_segs = pkt_in->nb_segs, i = 0, j;
    char *in_hdr = rte_pktmbuf_mtod(pkt_in, char*);
    char *pkt_addr;

    while (curr_pkt) {
        next_pkt = curr_pkt->next;
        curr_pkt->next = NULL;
        curr_pkt->nb_segs = 1;
        curr_pkt->pkt_len = curr_pkt->data_len;
        /* 1st mbuf in the chain already has all the headers */
        if (likely(nb_segs > 0)) {
            pkt_addr = rte_pktmbuf_prepend(curr_pkt, hdr_len);
            if (unlikely(pkt_addr == NULL)) {
                for(j=1;j<i;j++)
                    /* We cannot use dpdk_pfree() since the
                     * fragments may not have vr_packet info
                     */
                    rte_pktmbuf_free(pkts_out[j]);
                rte_pktmbuf_free(next_pkt);
                return -1;
            }
            rte_memcpy(pkt_addr, in_hdr, hdr_len);
        }
        pkts_out[nb_segs++] = curr_pkt;
        if (nb_segs >= nb_pkts_out)
            return -1;
        if (i >= total_segs)
            return -1;
        curr_pkt = next_pkt;
        i++;
    }
    return nb_segs;
}

/*
 * Updates the pointers to TCP and IPv6 headers
 */
static inline void
dpdk_gso_ipv6_tcp_update(struct rte_mbuf *m, struct dpdk_gso_state *state)
{
   state->ip6 = (struct ipv6_hdr *)(rte_pktmbuf_mtod(m, uint8_t *) + state->mac_hlen);
   state->tcp = (struct tcp_hdr *)((uint8_t*)(state->ip6) + state->ip_hlen);
   state->pay_len = m->pkt_len - state->hlen;
}

/*
 * Update the pointers to TCP and IPv4 headers
 */
static inline void
dpdk_gso_ipv4_tcp_update(struct rte_mbuf *m, struct dpdk_gso_state *state)
{
   state->ip = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, uint8_t *) + state->mac_hlen);
   state->tcp = (struct tcp_hdr *)((uint8_t*)(state->ip) + state->ip_hlen);
   state->pay_len = m->pkt_len - state->hlen;
}

/*
 * Sets properly the TCP and IPv6 headers
 */
static inline void
dpdk_gso_ipv6_tcp_internal(struct rte_mbuf *m, struct dpdk_gso_state *state)
{
   state->ip6->payload_len = rte_cpu_to_be_16(m->pkt_len -
                   state->mac_hlen - state->ip_hlen);

    /* TCP Sequence number */
   state->tcp->sent_seq = htonl(state->tcp_seq);

   if (state->tx_cksum_offload) {
       m->l2_len = state->mac_hlen;
       m->l3_len = state->ip_hlen;
       state->tcp->cksum = 0;
       state->tcp->cksum = rte_ipv6_phdr_cksum((struct ipv6_hdr *)state->ip6,
                                                                     m->ol_flags);
       m->ol_flags |= PKT_TX_IPV6;
       m->ol_flags |= PKT_TX_TCP_CKSUM;
   } else {
       /* TCP Checksum */
       state->tcp->cksum = 0;
       state->tcp->cksum = rte_ipv6_udptcp_cksum((struct ipv6_hdr *)state->ip6,
                                                            (uint8_t*)state->tcp);
   }
   state->tcp_seq += state->pay_len;
}

/*
 * Set properly the TCP and IPv4 headers
 */
static inline void
dpdk_gso_ipv4_tcp_internal(struct rte_mbuf *m, struct dpdk_gso_state *state)
{
    /* Update IP header */
   state->ip->packet_id = rte_cpu_to_be_16((state->ip_id)++);
   state->ip->total_length = rte_cpu_to_be_16(m->pkt_len - state->mac_hlen);

    /* TCP Sequence number */
   state->tcp->sent_seq = htonl(state->tcp_seq);

   if (state->tx_cksum_offload) {
       m->l2_len = state->mac_hlen;
       m->l3_len = state->ip_hlen;
       state->ip->hdr_checksum = 0;
       state->tcp->cksum = 0;
       state->tcp->cksum = rte_ipv4_phdr_cksum((struct ipv4_hdr *)state->ip,
                                                                     m->ol_flags);
       m->ol_flags |= PKT_TX_IP_CKSUM | PKT_TX_IPV4;
       m->ol_flags |= PKT_TX_TCP_CKSUM;
   } else {
       /* TCP Checksum */
       state->tcp->cksum = 0;
       state->tcp->cksum = rte_ipv4_udptcp_cksum((struct ipv4_hdr *)state->ip,
                                                            (uint8_t*)state->tcp);
       /* IP Checksum */
       state->ip->hdr_checksum = 0;
       state->ip->hdr_checksum = rte_ipv4_cksum(state->ip);
   }
   state->tcp_seq += state->pay_len;
}

/*
 * Init the state during the TCP segmentation
 */
static int
dpdk_gso_init_state(struct dpdk_gso_state *state,
                   struct rte_mbuf *m, int mac_hlen, int isipv6, int hw_cksum)
{
   uint32_t ip_hlen;

   if (isipv6) {
       ip_hlen = sizeof(struct ipv6_hdr);
       state->ip6 = (struct ipv6_hdr *)(rte_pktmbuf_mtod(m, uint8_t *) + mac_hlen);
       if (state->ip6->proto != VR_IP_PROTO_TCP)
           return -1;
       state->tcp = (struct tcp_hdr *)((uint8_t*)(state->ip6) + ip_hlen);
       state->update = dpdk_gso_ipv6_tcp_update;
       state->internal = dpdk_gso_ipv6_tcp_internal;
   } else {
       state->ip = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, uint8_t *) + mac_hlen);
       state->ip_id = rte_be_to_cpu_16(state->ip->packet_id);
       ip_hlen = ((state->ip->version_ihl) & 0xf) << 2;
       if (state->ip->next_proto_id != VR_IP_PROTO_TCP)
           return -1;
       state->tcp = (struct tcp_hdr *)((uint8_t*)state->ip + ip_hlen);
       state->update = dpdk_gso_ipv4_tcp_update;
       state->internal = dpdk_gso_ipv4_tcp_internal;
   }

   state->tx_cksum_offload = hw_cksum;
   state->mac_hlen = mac_hlen;
   state->ip_hlen = ip_hlen;
   state->tcp_hlen = ((state->tcp->data_off & 0xf0) >> 4) << 2;
   state->hlen = mac_hlen + ip_hlen + state->tcp_hlen;
   state->tcp_seq = ntohl(state->tcp->sent_seq);
   return 0;
}

/*
 * GSO on TCP/IP (v4 or v6)
 */
static int
dpdk_gso_segment_ip_tcp(struct rte_mbuf *pkt_in,
                        struct dpdk_gso_state *state,
                        struct rte_mbuf **mbufs_out,
                        const unsigned short nb_pkts_out,
                        uint16_t mss_size)
{
    int i = 0, nsegs = 0;

    /* Check that pkts_out is big enough to hold all segments */
    if (unlikely(mss_size * nb_pkts_out <
        (uint16_t)(pkt_in->pkt_len - state->hlen)))
        return -EINVAL;

    nsegs = dpdk_split_chained_mbuf(pkt_in, mbufs_out, nb_pkts_out,
                  state->hlen, mss_size);

    if (nsegs < 0)
        goto err;

    while (i < nsegs)
    {
        state->update(mbufs_out[i], state);

        /* Update TCP flags -
         * => Retain CWR only in the first segment and mask in the rest of
         *  the segments
         * => FIN and PSH flags are only applicable to the last segment
         */
        if (state->tcp) {
            if (i > 0)
                state->tcp->tcp_flags &= ~TCP_CWR_FLAG;
            if (i < nsegs-1)
                state->tcp->tcp_flags &= ~(TCP_FIN_FLAG | TCP_PSH_FLAG);
        }

        state->internal(mbufs_out[i], state);

        i++;
    }

    return nsegs;

err:
    return -1;
}

static void
dpdk_adjust_outer_header(struct rte_mbuf *m, uint16_t outer_header_len)
{
    struct vr_packet *pkt = vr_dpdk_mbuf_to_pkt(m);
    struct vr_ip *inner_ip = NULL;

    if (pkt->vp_type == VP_TYPE_IPOIP)
        inner_ip = rte_pktmbuf_mtod(m, struct vr_ip *);

    /* Outer header operations */
    char *outer_header_ptr = rte_pktmbuf_prepend(m, outer_header_len);

    uint16_t eth_hlen = dpdk_get_ether_header_len(outer_header_ptr);
    struct vr_ip *outer_ip = (struct vr_ip *)(outer_header_ptr + eth_hlen);
    outer_ip->ip_len = rte_cpu_to_be_16(rte_pktmbuf_pkt_len(m) - eth_hlen);

    /* Copy inner IP id to outer. Currently, the Agent diagnostics depends
     * on that. */
    if (inner_ip)
        outer_ip->ip_id = inner_ip->ip_id;
    else
        outer_ip->ip_id = rte_cpu_to_be_16(vr_generate_unique_ip_id());


    /* Adjust UDP length to match IP segment size */
    if (outer_ip->ip_proto == VR_IP_PROTO_UDP) {
        unsigned header_len = outer_ip->ip_hl * 4;
        struct vr_udp *udp = (struct vr_udp *)((char *)outer_ip +
                header_len);
        udp->udp_length = rte_cpu_to_be_16(
                rte_be_to_cpu_16(outer_ip->ip_len) - header_len);
    }

    /* Calculate the outer header IP checksum */
    outer_ip->ip_csum = vr_ip_csum(outer_ip);
}

int
dpdk_segment_packet(struct vr_packet *pkt, struct rte_mbuf *mbuf_in,
                 struct rte_mbuf **mbuf_out, const unsigned short out_num,
                 const unsigned short mss_size, bool do_outer_ip_csum)
{
    struct rte_mbuf *m;
    struct dpdk_gso_state state;
    int number_of_packets = 0, i;
    uint16_t outer_header_len;

    outer_header_len = pkt_get_inner_network_header_off(pkt) -
            pkt_head_space(pkt);

    if (dpdk_gso_init_state(&state, mbuf_in, outer_header_len,
                (pkt->vp_type == VP_TYPE_IP6OIP), do_outer_ip_csum) < 0)
        return -1;

    number_of_packets = dpdk_gso_segment_ip_tcp(mbuf_in, &state, mbuf_out,
                                                       out_num, mss_size);
    if (number_of_packets < 0)
        return number_of_packets;

    /* Adjust outer and inner IP headers for each segmented packets */
    for (i = 0; i < number_of_packets; i++)
    {
        m = mbuf_out[i];
        /* Get into the inner IP header */
        rte_pktmbuf_adj(m, outer_header_len);
        dpdk_adjust_outer_header(m, outer_header_len);
        m->l2_len = mbuf_in->l2_len;
        m->l3_len = mbuf_in->l3_len;
        m->vlan_tci = mbuf_in->vlan_tci;
        m->ol_flags |= mbuf_in->ol_flags;
    }

    return number_of_packets;
}
