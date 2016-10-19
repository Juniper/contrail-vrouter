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
#if 0
    union {
        uint32_t   s_ip4;
        uint8_t    s_ip6[VR_IP6_ADDRESS_LEN];
    } lesource;
    union {
        uint32_t   d_ip4;
        uint8_t    d_ip6[VR_IP6_ADDRESS_LEN];
    } ledest;
    uint16_t        source_port;
    uint16_t        dest_port;
    uint16_t        eh_type;    /* EthernetHeader type. */
#endif
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
};

#define le_ip4          leip.ip4
#define le_ip6          leip.ip6
#if 0
#define source_ip4      lesource.s_ip4
#define dest_ip4        ledest.d_ip4
#define source_ip6      lesource.s_ip6
#define dest_ip6        ledest.d_ip6
#endif

/* Flow key */
struct vr_dpdk_gro_flow_key {
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
    uint8_t proto;
    unsigned short vif_idx;
} __attribute__((packed));

/* Parameters used for hash table in unit test functions. Name set later. */
static struct rte_hash_parameters gro_tbl_params = {
    .entries = 1<<10,
    .key_len = sizeof(struct vr_dpdk_gro_flow_key),
    .hash_func = rte_jhash,
    .hash_func_init_val = 0,
    .socket_id = 0, /* TODO */
};

static inline int 
vr_dpdk_gro_init(unsigned lcore_id, struct vr_dpdk_lcore *lcore)
{
    char name[45];
    sprintf(name, "GRO_Table_lcore_%d", lcore_id);
    gro_tbl_params.name = name;
    lcore->gro.gro_tbl_handle = rte_hash_create(&gro_tbl_params);
    if (lcore->gro.gro_tbl_handle == NULL) {
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
