/*
 * Copyright (C) 2014 Juniper Networks.
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
 * vr_dpdk_gro.h -- DPDK GRO
 *
 */

#ifndef __VR_DPDK_GRO_H__
#define __VR_DPDK_GRO_H__

#include <rte_hash.h>
#include <rte_jhash.h>

struct gro_entry {
    struct rte_mbuf     *mbuf_head;
    struct rte_mbuf     *mbuf_tail;
    union {
        struct vr_ip   *ip4;
        struct vr_ip6  *ip6;
    } leip;
    uint16_t        src_vif_idx;
    uint16_t        nh_id;
    uint16_t        mbuf_cnt;
    uint32_t        p_len;      /* IP header payload length. */
    uint32_t        ulp_csum;   /* TCP, etc. checksum. */
    uint32_t        next_seq;   /* tcp_seq */
    uint32_t        ack_seq;    /* tcp_seq */
    uint32_t        tsval;
    uint32_t        tsecr;
    uint16_t        window;
    uint16_t        timestamp;  /* flag, not a TCP hdr field. */
    uint64_t        mtime;
    uint8_t         is_ipv6;
};

#define le_ip4          leip.ip4
#define le_ip6          leip.ip6

/* IPv4 Flow key */
struct vr_dpdk_gro_flow_key_v4 {
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
    uint8_t proto;
    unsigned short vif_idx;
} __attribute__((packed));

/* IPv6 Flow key */
struct vr_dpdk_gro_flow_key_v6 {
    uint8_t ip6_src[16];
    uint8_t ip6_dst[16];
    uint16_t port_src;
    uint16_t port_dst;
    uint8_t proto;
    unsigned short vif_idx;
} __attribute__((packed));


/* Parameters used for hash table in unit test functions. Name set later. */
static struct rte_hash_parameters gro_tbl_params_v4 = {
    .entries = 1<<3,
    .key_len = sizeof(struct vr_dpdk_gro_flow_key_v4),
    .hash_func = rte_jhash,
    .hash_func_init_val = 0,
    .socket_id = 0, /* TODO */
};

/* Parameters used for hash table in unit test functions. Name set later. */
static struct rte_hash_parameters gro_tbl_params_v6 = {
    .entries = 1<<3,
    .key_len = sizeof(struct vr_dpdk_gro_flow_key_v6),
    .hash_func = rte_jhash,
    .hash_func_init_val = 0,
    .socket_id = 0, /* TODO */
};

static inline int 
vr_dpdk_gro_init(unsigned lcore_id, struct vr_dpdk_lcore *lcore)
{
    char name[45];
    sprintf(name, "GRO_Table_v4_lcore_%d", lcore_id);
    gro_tbl_params_v4.name = name;
    lcore->gro.gro_tbl_v4_handle = rte_hash_create(&gro_tbl_params_v4);
    if (lcore->gro.gro_tbl_v4_handle == NULL) {
        printf("Warning! %s: lcore:%d, v4 nomem\n",__func__, lcore_id);
        return -ENOMEM;
    }
    sprintf(name, "GRO_Table_v6_lcore_%d", lcore_id);
    gro_tbl_params_v6.name = name;
    lcore->gro.gro_tbl_v6_handle = rte_hash_create(&gro_tbl_params_v6);
    if (lcore->gro.gro_tbl_v6_handle == NULL) {
        printf("Warning! %s: lcore:%d, v6 nomem\n",__func__, lcore_id);
        return -ENOMEM;
    }
    return 0;
}

typedef enum 
{
    GRO_ERROR = 1,
    GRO_MERGED,
    GRO_NORMAL,
    GRO_NOT_APPLICABLE,
    GRO_CANNOT,
}vr_dpdk_gro_ret_t;

int
vr_dpdk_gro_rx(struct vr_dpdk_lcore* lcore, struct vr_interface *vif, struct vr_packet *pkt);
#endif /* __VR_DPDK_GRO_H__ */
