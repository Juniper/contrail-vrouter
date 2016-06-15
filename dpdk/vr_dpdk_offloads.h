/*
 * vr_dpdk_gso.h - header for DPDK GSO/GRO functions.
 *
 *
 * Copyright (c) 2016 Juniper Networks.
 */

#ifndef __VR_DPDK_OFFLOADS_H__
#define __VR_DPDK_OFFLOADS_H__

#define TCP_CWR_FLAG 0x80

enum vr_dpdk_gso_type {
   GSO_NONE,
   GSO_TCP4,
   GSO_TCP6,
   GSO_END_OF_TYPE
};

int (*vr_dpdk_gso_functions[GSO_END_OF_TYPE]) 
                      (struct vr_packet*, struct rte_mbuf*, uint32_t);

static inline uint32_t vr_dpdk_get_gso_type (uint32_t flags)
{
    switch(flags)
    {
        case PKT_RX_GSO_TCP4: 
            return GSO_TCP4;
        default:
            return GSO_NONE;
    }
}

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

void
dpdk_gso_init_state(struct dpdk_gso_state *state, 
                   struct rte_mbuf *m, int mac_hlen, int isipv6, int hw_cksum);

int
dpdk_gso_segment_ip_tcp(struct rte_mbuf *pkt_in,
                        struct dpdk_gso_state *state, 
                        struct rte_mbuf **mbufs_out,
                        const unsigned short nb_pkts_out,
                        uint16_t mss_size,
                        struct rte_mempool *pool_direct,
                        struct rte_mempool *pool_indirect);

#endif /* __VR_DPDK_OFFLOADS_H__ */
