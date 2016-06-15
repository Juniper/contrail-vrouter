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
 * vr_dpdk_offloads.c -- DPDK GSO/GRO implementation
 *
 */
#include "vr_dpdk.h"
#include "vr_dpdk_offloads.h"

#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ip_frag.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_port_ethdev.h>
#include <rte_eth_af_packet.h>
#include <rte_eth_ctrl.h>

static inline void __free_fragments(struct rte_mbuf *mb[], uint32_t num)
{
	uint32_t i;
	for (i = 0; i != num; i++)
		rte_pktmbuf_free(mb[i]);
}

/*
 * Create a queue of packets/segments which fit the given frag_size + hdr_len.
 * pkt_in points to mbuf chain to be segmented.
 * This function splits the payload (pkt_in->pkt_len - hdr_len)
 * into segments of length MSS bytes and then copy the first hdr_len bytes
 * from pkt_in at the top of each segment. The packets are stored at pkts_out array
 *
 * Return the number of segments on success and a negative error on failure.
 */
static int32_t
dpdk_segment_mbuf(struct rte_mbuf *pkt_in, struct rte_mbuf **pkts_out, 
                    uint16_t nb_pkts_out, uint16_t hdr_len, uint16_t frag_size,
                    struct rte_mempool *pool_direct,
                    struct rte_mempool *pool_indirect)
{
    struct rte_mbuf *in_seg = NULL;
    uint32_t out_pkt_pos, in_seg_data_pos;
    uint32_t more_in_segs;
    uint8_t *in_hdr;

    if (unlikely(nb_pkts_out * frag_size <
        (uint16_t)(pkt_in->pkt_len - hdr_len)))
        return -EINVAL;

    in_seg = pkt_in;
    in_hdr = rte_pktmbuf_mtod(pkt_in, uint8_t*);
    in_seg_data_pos = hdr_len;
    out_pkt_pos = 0;

    more_in_segs = 1;
    while (likely(more_in_segs)) {
        struct rte_mbuf *out_pkt = NULL, *out_seg_prev = NULL;
        uint32_t more_out_segs;
        uint8_t *out_hdr;

        /* Allocate direct buffer */
        out_pkt = rte_pktmbuf_alloc(pool_direct);
        if (unlikely(out_pkt == NULL)) {
            __free_fragments(pkts_out, out_pkt_pos);
            return -ENOMEM;
        }
        /* Reserve space for the header that will be copied later */
        out_pkt->data_len = hdr_len;
        out_pkt->pkt_len = hdr_len;

        /* Copy the other relevant mbuf fields */
        out_pkt->vlan_tci = pkt_in->vlan_tci;
        out_pkt->ol_flags = pkt_in->ol_flags;

        /* Mask flags which are not applicable */
        out_pkt->ol_flags &= ~(PKT_RX_GSO_TCP4);

        out_seg_prev = out_pkt;
        more_out_segs = 1;
        while (likely(more_out_segs && more_in_segs)) {
            struct rte_mbuf *out_seg = NULL;
            uint32_t len;

            /* Allocate indirect buffer */
            out_seg = rte_pktmbuf_alloc(pool_indirect);
            if (unlikely(out_seg == NULL)) {
                rte_pktmbuf_free(out_pkt);
                __free_fragments(pkts_out, out_pkt_pos);
                return -ENOMEM;
            }
            out_seg_prev->next = out_seg;
            out_seg_prev = out_seg;

            /* Prepare indirect buffer */
            rte_pktmbuf_attach(out_seg, in_seg);
            len = frag_size - out_pkt->pkt_len;
            if (len > (in_seg->data_len - in_seg_data_pos)) {
                len = in_seg->data_len - in_seg_data_pos;
            }
            out_seg->data_off = in_seg->data_off + in_seg_data_pos;
            out_seg->data_len = (uint16_t)len;
            out_pkt->pkt_len = (uint16_t)(len +
                out_pkt->pkt_len);
            out_pkt->nb_segs += 1;
            in_seg_data_pos += len;

            /* Current output packet (i.e. fragment) done ? */
            if (unlikely(out_pkt->pkt_len >= frag_size))
                more_out_segs = 0;

            /* Current input segment done ? */
            if (unlikely(in_seg_data_pos >= in_seg->data_len)) {
                in_seg = in_seg->next;
                in_seg_data_pos = 0;

                if (unlikely(in_seg == NULL))
                    more_in_segs = 0;
            }
        }

        /* Copy the header */
        out_hdr = rte_pktmbuf_mtod(out_pkt, uint8_t *);
        rte_memcpy(out_hdr, in_hdr, (uint16_t)out_pkt->data_len);

        /* Write the fragment to the output list */
        pkts_out[out_pkt_pos] = out_pkt;
        out_pkt_pos ++;
    }
    return out_pkt_pos;
}

/*
 * Update the pointers to TCP and IPv4 headers
 */
static inline void
dpdk_gso_ipv4_tcp_update(struct rte_mbuf *m, struct dpdk_gso_state *state)
{
   state->ip = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, uint8_t *) + 
                                                            state->mac_hlen);
   state->tcp = (struct tcp_hdr *)((uint8_t*)(state->ip) + state->ip_hlen);
   state->pay_len = m->pkt_len - state->hlen;
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
       state->tcp->cksum = dpdk_ipv4_udptcp_cksum(m, (struct ipv4_hdr *)state->ip, 
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
void
dpdk_gso_init_state(struct dpdk_gso_state *state, 
                   struct rte_mbuf *m, int mac_hlen, int isipv6, int hw_cksum)
{
   uint32_t ip_hlen;

   if (isipv6) {
       ip_hlen = sizeof(struct ipv6_hdr);
       state->ip6 = (struct ipv6_hdr *)(rte_pktmbuf_mtod(m, uint8_t *) + mac_hlen);
       state->tcp = (struct tcp_hdr *)((uint8_t*)(state->ip6) + ip_hlen);
#ifdef VR_SUPPORT_GSO_IPV6 
       state->update = gso_ipv6_tcp_update;
       state->internal = gso_ipv6_tcp_internal;
#endif
   } else {
       state->ip = (struct ipv4_hdr *)(rte_pktmbuf_mtod(m, uint8_t *) + mac_hlen);
       state->ip_id = rte_be_to_cpu_16(state->ip->packet_id);
       ip_hlen = ((state->ip->version_ihl) & 0xf) << 2;
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
}

/*
 * GSO on TCP/IP (v4 or v6)
 */
int
dpdk_gso_segment_ip_tcp(struct rte_mbuf *pkt_in,
                        struct dpdk_gso_state *state, 
                        struct rte_mbuf **mbufs_out,
                        const unsigned short nb_pkts_out,
                        uint16_t mss_size,
                        struct rte_mempool *pool_direct,
                        struct rte_mempool *pool_indirect)
{
    int i = 0, nsegs = 0;

    /* Check that pkts_out is big enough to hold all fragments */
    if (unlikely(mss_size * nb_pkts_out <
        (uint16_t)(pkt_in->pkt_len - state->hlen)))
        return -EINVAL;

    nsegs = dpdk_segment_mbuf(pkt_in, mbufs_out, VR_DPDK_FRAG_MAX_IP_SEGS,
                  state->hlen, mss_size, pool_direct, pool_indirect);
    if (nsegs < 0)
        goto err;

    while (i < nsegs) 
    {
        state->update(mbufs_out[i], state);

        /* Update TCP flags */
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
