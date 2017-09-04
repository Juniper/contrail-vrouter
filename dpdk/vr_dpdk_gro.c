/*
 * Copyright (C) 2017 Juniper Networks.
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
 * vr_dpdk_gro.c -- TCP Offloads on the receiver
 *
 * This is an adaptation of FreeBSD's tcp_lro.c.
 * Copyright (c) 2007, Myricom Inc.
 * Copyright (c) 2008, Intel Corporation.
 * Copyright (c) 2012 The FreeBSD Foundation
 * All rights reserved.
 * BSD LICENSE
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

#define GRO_TABLE_NAME_LEN 45

int
vr_dpdk_gro_init(unsigned lcore_id, struct vr_dpdk_lcore *lcore)
{
    /* Parameters used for hash tables. Name is set later. */
    struct rte_hash_parameters gro_tbl_params_v4 = {
        .entries = 1<<3,
        .key_len = sizeof(struct vr_dpdk_gro_flow_key_v4),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = 0, /* TODO */
    };
    struct rte_hash_parameters gro_tbl_params_v6 = {
        .entries = 1<<3,
        .key_len = sizeof(struct vr_dpdk_gro_flow_key_v6),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
        .socket_id = 0, /* TODO */
    };

    char gro_v4_tbl_name[GRO_TABLE_NAME_LEN], gro_v6_tbl_name[GRO_TABLE_NAME_LEN];

    snprintf(gro_v4_tbl_name, sizeof(gro_v4_tbl_name), "GRO_Table_v4_lcore_%d", lcore_id);
    gro_tbl_params_v4.name = gro_v4_tbl_name;
    lcore->gro.gro_tbl_v4_handle = rte_hash_create(&gro_tbl_params_v4);
    if (lcore->gro.gro_tbl_v4_handle == NULL) {
        RTE_LOG(ERR, VROUTER, "Warning! %s: lcore:%d, Unable to allocate memory "
                          "for IPv4 GRO table\n", __func__, lcore_id);
        return -ENOMEM;
    }
    snprintf(gro_v6_tbl_name, sizeof(gro_v6_tbl_name), "GRO_Table_v6_lcore_%d", lcore_id);
    gro_tbl_params_v6.name = gro_v6_tbl_name;
    lcore->gro.gro_tbl_v6_handle = rte_hash_create(&gro_tbl_params_v6);
    if (lcore->gro.gro_tbl_v6_handle == NULL) {
        RTE_LOG(ERR, VROUTER, "Warning! %s: lcore:%d, Unable to allocate memory "
                          "for IPv6 GRO table\n", __func__, lcore_id);
        return -ENOMEM;
    }
    return 0;
}


static uint16_t
dpdk_gro_csum_tcph(struct vr_tcp *tcph)
{
    uint32_t ch;
    uint16_t *p, l;

    ch = tcph->tcp_csum = 0x0000;
    l = VR_TCP_OFFSET(tcph->tcp_offset_r_flags);
    p = (uint16_t *)tcph;
    while (l > 0) {
        ch += (*p);
        p++;
        ch += (*p);
        p++;
        l--;
    }
    while (ch > 0xffff)
        ch = (ch >> 16) + (ch & 0xffff);

    return (ch & 0xffff);
}

static uint16_t
dpdk_gro_rx_csum_fixup(struct gro_entry *entry, uint8_t is_ipv6, void *nw_hdr,
                    struct vr_tcp *tcph, uint16_t tcp_data_len, uint16_t csum)
{
    uint32_t c;
    uint16_t cs;

    c = csum;

    /* For first packet, remove just the length from checksum
     * For subsequent packets, remove the checksum of full TCP header
     */
    if (!is_ipv6) {
        struct vr_ip* ip4 = nw_hdr;
        if (entry->mbuf_cnt == 1)
            cs = rte_be_to_cpu_16(ip4->ip_len) - sizeof(*ip4);
        else
            cs = rte_be_to_cpu_16(rte_ipv4_phdr_cksum((const struct ipv4_hdr*)ip4,0));
    } else {
        struct vr_ip6* ip6 = nw_hdr;
        if (entry->mbuf_cnt == 1)
            cs = rte_be_to_cpu_16(ip6->ip6_plen);
        else
            cs = rte_be_to_cpu_16(rte_ipv6_phdr_cksum((const struct ipv6_hdr*)ip6,0));
    }

    cs = ~cs;
    c += cs;

    /* Remove TCP header csum. */
    cs = rte_be_to_cpu_16(~dpdk_gro_csum_tcph(tcph));
    c += cs;
    while (c > 0xffff)
        c = (c >> 16) + (c & 0xffff);

    return (c & 0xffff);
}

static int
dpdk_gro_flush(struct gro_ctrl *gro, void *key, struct gro_entry *entry)
{
    int ret;
    struct vr_tcp *tcph = NULL;
    struct vr_interface *vif = NULL;
    struct vrouter *router = vrouter_get(0);
    struct rte_mbuf *m = entry->mbuf_head;
    struct vr_packet *pkt = vr_dpdk_mbuf_to_pkt(m);
    struct vr_forwarding_md fmd;
    uint32_t cl;
    uint16_t c;
    unsigned short drop_reason;
    struct vr_nexthop *nh;

    if (entry->mbuf_cnt > 1) {

        if (!entry->is_ipv6) {
            /* Fix IP header checksum for new length. */
            struct vr_ip *ip4 = entry->le_ip4;
            c = rte_be_to_cpu_16(~ip4->ip_csum);
            cl = c;
            c = rte_be_to_cpu_16(~ip4->ip_len);
            cl += c + entry->p_len;
            while (cl > 0xffff)
                cl = (cl >> 16) + (cl & 0xffff);
            c = cl;
            ip4->ip_csum = rte_cpu_to_be_16(~c);

            entry->le_ip4->ip_len = rte_cpu_to_be_16(entry->p_len);
            tcph = (struct vr_tcp *)(entry->le_ip4 + 1);
            m->ol_flags |= PKT_RX_GSO_TCP4;
        } else {
            struct vr_ip6 *ip6 = entry->le_ip6;
            ip6->ip6_plen = rte_cpu_to_be_16(entry->p_len - sizeof(struct vr_ip6));
            tcph = (struct vr_tcp *)(entry->le_ip6 + 1);
            m->ol_flags |= PKT_RX_GSO_TCP6;
        }
        m->pkt_len =
               entry->p_len + pkt_get_network_header_off(pkt) - pkt_head_space(pkt);
        m->nb_segs = entry->mbuf_cnt;
        m->tso_segsz = entry->seg_sz;

        /* Incorporate the latest ACK into the TCP header. */
        tcph->tcp_ack = rte_cpu_to_be_32(entry->ack_seq);
        tcph->tcp_win = rte_cpu_to_be_16(entry->window);
        /* Incorporate latest timestamp into the TCP header. */
        if (entry->timestamp != 0) {
            uint32_t *ts_ptr;

            ts_ptr = (uint32_t *)(tcph + 1);
            ts_ptr[1] = rte_cpu_to_be_32(entry->tsval);
            ts_ptr[2] = rte_cpu_to_be_32(entry->tsecr);
        }

        /* Update the TCP header checksum. */
        if (!entry->is_ipv6)
            entry->ulp_csum += entry->p_len - sizeof(struct vr_ip);
        else
            entry->ulp_csum += entry->p_len - sizeof(struct vr_ip6);

        entry->ulp_csum += rte_cpu_to_be_16(dpdk_gro_csum_tcph(tcph));
        while (entry->ulp_csum > 0xffff)
            entry->ulp_csum = (entry->ulp_csum >> 16) +
                (entry->ulp_csum & 0xffff);
        tcph->tcp_csum = entry->ulp_csum & 0xffff;
        tcph->tcp_csum = rte_cpu_to_be_16(~tcph->tcp_csum);
    }

    gro->gro_queued += entry->mbuf_cnt;
    gro->gro_flushed++;

    /* Delete flow entry from hash table */
    if (!entry->is_ipv6)
        ret = rte_hash_del_key(gro->gro_tbl_v4_handle, key);
    else
        ret = rte_hash_del_key(gro->gro_tbl_v6_handle, key);
    ASSERT(ret >= 0);

    nh = __vrouter_get_nexthop(router, entry->nh_id);
    if (!nh) {
        drop_reason = VP_DROP_INVALID_NH;
        goto drop;
    }
    vif = nh->nh_dev;
    if ((vif == NULL) || (!vif_is_virtual(vif))) {
        drop_reason = VP_DROP_INVALID_IF;
        goto drop;
    }

    /* Validate the gen_id of the vif */
    if (unlikely((vif->vif_idx != entry->dst_vif_idx) ||
                 (vif->vif_gen != entry->dst_vif_gen))) {
        drop_reason = VP_DROP_INVALID_IF;
        goto drop;
    }

    if (nh->nh_family == AF_BRIDGE) {
        if (!rte_pktmbuf_prepend(m, VR_ETHER_HLEN)) {
            drop_reason = VP_DROP_INVALID_PACKET;
            goto drop;
        }
    }

    pkt = vr_dpdk_packet_get(m, NULL);
    if (!pkt) {
        drop_reason = VP_DROP_INVALID_IF;
        goto drop;
    }

    /*
     * since vif was not available when we did vr_dpdk_packet_get, set vif
     * manually here
     */
    vif = __vrouter_get_interface(router, entry->src_vif_idx);
    if (!vif) {
        drop_reason = VP_DROP_INVALID_IF;
        goto drop;
    }

    /* Validate the gen_id of the vif */
    if (unlikely(vif->vif_gen != entry->src_vif_gen)) {
        drop_reason = VP_DROP_INVALID_IF;
        goto drop;
    }

    pkt->vp_if = vif;

    vr_init_forwarding_md(&fmd);
    fmd.fmd_dvrf = nh->nh_dev->vif_vrf;

    if (nh->nh_family == AF_BRIDGE) {
        if (vr_pkt_type(pkt, 0, &fmd)) {
            drop_reason = VP_DROP_INVALID_PACKET;
            goto drop;
        }
    } else {
        if (vr_ip_is_ip4((struct vr_ip *)pkt_data(pkt))) {
            pkt->vp_type = VP_TYPE_IP;
        } else if (vr_ip_is_ip6((struct vr_ip *)pkt_data(pkt))) {
            pkt->vp_type = VP_TYPE_IP6;
        } else {
            drop_reason = VP_DROP_INVALID_PROTOCOL;
            goto drop;
        }

        pkt_set_network_header(pkt, pkt->vp_data);
        pkt_set_inner_network_header(pkt, pkt->vp_data);
    }

    pkt->vp_flags |= VP_FLAG_FLOW_SET | VP_FLAG_GROED;
    nh_output(pkt, nh, &fmd);
    rte_free(entry);
    return GRO_MERGED;

drop:
    vr_dpdk_pfree(m, vif, drop_reason);
    rte_free(entry);
    return 0;
}

void
dpdk_gro_free_all_flows(struct vr_dpdk_lcore *lcore)
{
    struct gro_entry *entry;
    uint32_t iter = 0;
    void *next_key;
    struct gro_ctrl *gro = &lcore->gro;
    if (gro->gro_tbl_v4_handle != NULL) {
        while (rte_hash_iterate(gro->gro_tbl_v4_handle, (const void**)&next_key,
                                                  (void**)&entry, &iter) >= 0) {
            vr_dpdk_pfree(entry->mbuf_head, NULL, VP_DROP_DISCARD);
            rte_free(entry);
        }
        rte_hash_reset(gro->gro_tbl_v4_handle);
    }
    iter = 0;
    if (gro->gro_tbl_v6_handle != NULL) {
        while (rte_hash_iterate(gro->gro_tbl_v6_handle, (const void**)&next_key,
                                                  (void**)&entry, &iter) >= 0) {
            vr_dpdk_pfree(entry->mbuf_head, NULL, VP_DROP_DISCARD);
            rte_free(entry);
        }
        rte_hash_reset(gro->gro_tbl_v6_handle);
    }
}

void
dpdk_gro_flush_all_inactive(struct vr_dpdk_lcore *lcore)
{
    uint32_t iter = 0;
    void *next_key;
    struct gro_entry *entry;
    struct gro_ctrl *gro = &lcore->gro;
    uint64_t cur_cycles = 0, diff_cycles;
    const uint64_t gro_flush_cycles = 100 * VR_DPDK_TX_FLUSH_LOOPS;

    if (gro->gro_tbl_v4_handle != NULL) {
        cur_cycles = lcore->lcore_fwd_loops;
        /* Iterate through the hash table */
        while (rte_hash_iterate(gro->gro_tbl_v4_handle, (const void**)&next_key,
                                                  (void**)&entry, &iter) >= 0) {
            diff_cycles = cur_cycles - entry->mtime;
            if (unlikely(gro_flush_cycles < diff_cycles)) {
                /* Flush flow */
                dpdk_gro_flush(gro, next_key, entry);
                lcore->gro.gro_flush_inactive_flows++;
            }
        }
    }

    iter = 0;
    if (gro->gro_tbl_v6_handle != NULL) {
        cur_cycles = lcore->lcore_fwd_loops;
        /* Iterate through the hash table */
        while (rte_hash_iterate(gro->gro_tbl_v6_handle, (const void**)&next_key,
                                                  (void**)&entry, &iter) >= 0) {
            diff_cycles = cur_cycles - entry->mtime;
            if (unlikely(gro_flush_cycles < diff_cycles)) {
                /* Flush flow */
                dpdk_gro_flush(gro, next_key, entry);
                lcore->gro.gro_flush_inactive_flows++;
            }
        }
    }
}

int
dpdk_gro_process(struct vr_packet *pkt, struct vr_interface *vif, bool l2_pkt)
{
    struct vr_dpdk_gro_flow_key_v4 flow4;
    struct vr_dpdk_gro_flow_key_v6 flow6;
    struct gro_entry *entry;
    struct rte_mbuf *m;
    void *nw_hdr;
    struct vr_tcp *tcph = NULL;
    uint16_t tcp_data_len, ip_pkt_len, l;
    uint32_t *ts_ptr;
    int32_t ret;
    unsigned short csum;
    unsigned short src_vif_idx = 0, nh_id = 0;
    unsigned lcore_id;
    struct vr_dpdk_lcore *lcore;
    uint8_t is_ipv6 = 0, flush = 0;
    void *key = NULL;
    struct vrouter *router;
    struct vr_interface *src_vif;
    struct vr_nexthop *nh;
    struct vr_gro *gro;

    if (vif) {
        struct vr_interface_stats *gro_vif_stats;
        gro_vif_stats = vif_get_stats(vif, vr_get_cpu());
        if (gro_vif_stats) {
            gro_vif_stats->vis_opackets++;
            gro_vif_stats->vis_obytes += pkt_len(pkt);
        }
    }

    /* Normal processing for VMs if -
     * => They dont require GRO (like DPDK VM's)
     * => They dont support mergeable buffers
     */
    if ((vif->vif_flags &
                (VIF_FLAG_GRO_NEEDED | VIF_FLAG_MRG_RXBUF)) !=
                (VIF_FLAG_GRO_NEEDED | VIF_FLAG_MRG_RXBUF)) {
        return 0;
    }

    lcore_id = rte_lcore_id();
    lcore = vr_dpdk.lcores[lcore_id];

    /* Packets arriving through non-Fwd cores - Normal processing */
    if (unlikely((lcore->gro.gro_tbl_v4_handle == NULL) ||
            (lcore->gro.gro_tbl_v6_handle == NULL))){
        return 0;
    }

    m = vr_dpdk_pkt_to_mbuf(pkt);
    nw_hdr = m->buf_addr + pkt_get_network_header_off(pkt);
    router = vrouter_get(0);
    /* Adjust mbuf */
    m->data_off = pkt_head_space(pkt);
    m->pkt_len = pkt_len(pkt);
    m->data_len = pkt_head_len(pkt);

    /* get the vif_idx and nh_id */
    gro = rte_pktmbuf_mtod(m, struct vr_gro *);
    src_vif_idx = gro->vg_vif_id;
    nh_id = gro->vg_nh_id;
    rte_pktmbuf_adj(m, sizeof(struct vr_gro));
    pkt_pull(pkt, sizeof(struct vr_gro));

    src_vif = __vrouter_get_interface(router, src_vif_idx);

    /* Make sure nh points to a virtual vif */
    nh = __vrouter_get_nexthop(router, nh_id);
    if ((nh == NULL) || (nh->nh_dev == NULL)
            || (!vif_is_virtual(nh->nh_dev))) {
        ret = GRO_NORMAL;
        goto func_exit;
    }

    /* Can't handle chained mbufs */
    if (m->nb_segs > 1) {
        flush = 1;
    }

    /* Parse IP header */
    if (vr_ip_is_ip6(nw_hdr)) {
        struct vr_ip6 *ip6 = nw_hdr;
        is_ipv6 = 1;
        flow6.proto = ip6->ip6_nxt;
        /* For non TCP packets, no GRO */
        if (flow6.proto != VR_IP_PROTO_TCP) {
            ret = GRO_NOT_APPLICABLE;
            goto func_exit;
        }
        rte_memcpy(&flow6.ip6_src, ip6->ip6_src, sizeof(flow6.ip6_src));
        rte_memcpy(&flow6.ip6_dst, ip6->ip6_dst, sizeof(flow6.ip6_dst));
        tcph = (struct vr_tcp *)(nw_hdr + sizeof(*ip6));
        flow6.port_src = rte_be_to_cpu_16(tcph->tcp_sport);
        flow6.port_dst = rte_be_to_cpu_16(tcph->tcp_dport);
        flow6.vif_idx = vif->vif_idx;
        ip_pkt_len = rte_be_to_cpu_16(ip6->ip6_plen) + sizeof(struct vr_ip6);
        tcp_data_len = rte_be_to_cpu_16(ip6->ip6_plen);
        key = &flow6;
    } else if (vr_ip_is_ip4(nw_hdr)) {
        struct vr_ip *ip4 = nw_hdr;
        unsigned int hlen = 0;
        hlen = ip4->ip_hl * 4;
        flow4.proto = ip4->ip_proto;
        /* For non TCP packets, no GRO */
        if (flow4.proto != VR_IP_PROTO_TCP) {
            ret = GRO_NOT_APPLICABLE;
            goto func_exit;
        }
        /* Ensure the packet is not fragmented. */
        else if (ip4->ip_frag_off & rte_cpu_to_be_16(IP_MF|IP_OFFMASK)) {
            flush = 1;
        }
        /* .. and there are no options. */
        else if (hlen != sizeof (*ip4)) {
            flush = 1;
        }
        flow4.ip_src = ip4->ip_saddr;
        flow4.ip_dst = ip4->ip_daddr;
        tcph = (struct vr_tcp *)(nw_hdr + hlen);
        flow4.port_src = rte_be_to_cpu_16(tcph->tcp_sport);
        flow4.port_dst = rte_be_to_cpu_16(tcph->tcp_dport);
        flow4.vif_idx = vif->vif_idx;
        ip_pkt_len = rte_be_to_cpu_16(ip4->ip_len);
        tcp_data_len = ip_pkt_len - (ip4->ip_hl << 2);
        key = &flow4;
    } else {
        ret = GRO_NOT_APPLICABLE;
        goto func_exit;
    }
    csum = rte_be_to_cpu_16(tcph->tcp_csum);

    /* Check TCP header constraints */

    /* Ensure no bits set besides ACK. */
    if (VR_TCP_FLAGS(tcph->tcp_offset_r_flags) & (~VR_TCP_FLAG_ACK)) {
        flush = 1;
    }

    /*
     * Check for timestamps.
     * Since the only option we handle are timestamps, we only have to
     * handle the simple case of aligned timestamps.
     */
    l = VR_TCP_OFFSET(tcph->tcp_offset_r_flags) << 2;
    tcp_data_len -= l;
    l -= sizeof(*tcph);
    ts_ptr = (uint32_t *)(tcph + 1);
    if (l != 0 && (unlikely(l != TCPOLEN_TSTAMP_APPA) ||
        (*ts_ptr != rte_cpu_to_be_32(TCPOPT_NOP<<24|TCPOPT_NOP<<16|
        TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)))) {
        flush = 1;
    }

    if (likely(flush == 0)) {
        /* Check TCP checksum */
        tcph->tcp_csum = 0;
        if (!is_ipv6)
            tcph->tcp_csum = rte_ipv4_udptcp_cksum(nw_hdr, tcph);
        else
            tcph->tcp_csum = rte_ipv6_udptcp_cksum(nw_hdr, tcph);

        if (tcph->tcp_csum == 0xffff)
            tcph->tcp_csum = 0;

        if (csum != rte_be_to_cpu_16(tcph->tcp_csum)) {
            vr_dpdk_pfree(m, vif, VP_DROP_CKSUM_ERR);
            ret = GRO_MERGED;
            goto func_exit;
        }
    }

    if (!is_ipv6)
        ret = rte_hash_lookup_data(lcore->gro.gro_tbl_v4_handle, &flow4, (void*)&entry);
    else
        ret = rte_hash_lookup_data(lcore->gro.gro_tbl_v6_handle, &flow6, (void*)&entry);

    if (ret >= 0) {
        /* Update flow */

        /* Check if packet needs to be flushed */
        if (flush) {
            dpdk_gro_flush(&lcore->gro, key, entry);
            ret = GRO_CANNOT;
            goto func_exit;
        }

        /* Flush now if appending will result in overflow. */
        if (entry->p_len > (65535 - tcp_data_len)) {
            dpdk_gro_flush(&lcore->gro, key, entry);
            goto create;
        }

        /* Try to append the new segment. */
        if (unlikely(rte_be_to_cpu_32(tcph->tcp_seq) != entry->next_seq ||
           (tcp_data_len == 0))) {
            /* Out of order packet or duplicate ACK. */
            dpdk_gro_flush(&lcore->gro, key, entry);
            ret = GRO_CANNOT;
            goto func_exit;
        }

        if (l != 0) {
            uint32_t tsval = rte_be_to_cpu_32(*(ts_ptr + 1));
            /* Make sure timestamp values are increasing.
             * Also make sure the timestamp echo reply value is valid.
             * Note: timestamp echo reply is valid if its value is not 0.
             */
            if (unlikely(entry->tsval > tsval ||
                rte_be_to_cpu_32(*(ts_ptr + 2)) == 0)) {
                dpdk_gro_flush(&lcore->gro, key, entry);
                ret = GRO_CANNOT;
                goto func_exit;
            }
            entry->tsval = tsval;
            entry->tsecr = rte_be_to_cpu_32(*(ts_ptr + 2));
        }

        entry->next_seq += tcp_data_len;
        entry->ack_seq = rte_be_to_cpu_32(tcph->tcp_ack);
        entry->window = rte_be_to_cpu_16(tcph->tcp_win);
        entry->mbuf_cnt++;
        entry->ulp_csum += dpdk_gro_rx_csum_fixup(entry, is_ipv6, nw_hdr, tcph, tcp_data_len, ~csum);

        entry->p_len += tcp_data_len;

        /*
         * Adjust the mbuf so that rte_pktmbuf_mtod(m) points to the first byte of
         * the ULP payload.  Adjust the mbuf to avoid complications and
         * append new segment to existing mbuf chain.
         */
        rte_pktmbuf_adj(m, rte_pktmbuf_data_len(m) - tcp_data_len);

        entry->mbuf_tail->next = m;
        entry->mbuf_tail = rte_pktmbuf_lastseg(m);

        /* If segment size is different, flush */
        if (entry->seg_sz != tcp_data_len) {
            dpdk_gro_flush(&lcore->gro, key, entry);
            ret = GRO_MERGED;
            goto func_exit;
        }

        /* Save cycles */
        entry->mtime = lcore->lcore_fwd_loops;

        ret = GRO_MERGED;
    } else {
        /* Create new flow */
        struct gro_entry *entry;
create:
        if (tcp_data_len == 0) {
            ret = GRO_CANNOT;
            goto func_exit;
        } else if (flush) {
            ret = GRO_CANNOT;
            goto func_exit;
        }

        entry = rte_zmalloc("GRO_entry", sizeof(*entry), RTE_CACHE_LINE_SIZE);
        if (unlikely(entry == NULL)) {
            ret = GRO_ERROR;
            goto func_exit;
        }
        entry->is_ipv6 = is_ipv6;
        entry->src_vif_idx = src_vif_idx;
        if (likely(src_vif != NULL))
            entry->src_vif_gen = src_vif->vif_gen;
        entry->dst_vif_idx = nh->nh_dev->vif_idx;
        entry->dst_vif_gen = nh->nh_dev->vif_gen;
        entry->nh_id = nh_id;
        entry->mtime = lcore->lcore_fwd_loops;
        entry->p_len = ip_pkt_len;
        entry->next_seq = rte_be_to_cpu_32(tcph->tcp_seq) + tcp_data_len;
        entry->ack_seq = rte_be_to_cpu_32(tcph->tcp_ack);
        entry->window = rte_be_to_cpu_16(tcph->tcp_win);
        entry->seg_sz = tcp_data_len;
        if (!is_ipv6)
            entry->le_ip4 = nw_hdr;
        else
            entry->le_ip6 = nw_hdr;
        entry->mbuf_cnt++;
        if (unlikely(l != 0)) {
            entry->timestamp = 1;
            entry->tsval = rte_be_to_cpu_32(*(ts_ptr + 1));
            entry->tsecr = rte_be_to_cpu_32(*(ts_ptr + 2));
        }
        entry->mbuf_head = m;
        entry->mbuf_tail = rte_pktmbuf_lastseg(m);

        entry->ulp_csum = dpdk_gro_rx_csum_fixup(entry, is_ipv6, nw_hdr, tcph, tcp_data_len, ~csum);
        tcph->tcp_csum = rte_cpu_to_be_16(csum);/* Restore checksum on first packet. */
        lcore->gro.gro_flows++;

        if (!is_ipv6) {
            ret = (rte_hash_add_key_data(lcore->gro.gro_tbl_v4_handle, &flow4, entry) < 0)?
                                       GRO_ERROR : GRO_MERGED;
        } else {
            ret = (rte_hash_add_key_data(lcore->gro.gro_tbl_v6_handle, &flow6, entry) < 0)?
                                       GRO_ERROR : GRO_MERGED;
        }

        if (ret == GRO_MERGED) {
            /* point mbuf to network header */
            rte_pktmbuf_adj(m, pkt_get_network_header_off(pkt)- pkt_head_space(pkt));
            pkt_pull(pkt, pkt_get_network_header_off(pkt)- pkt_head_space(pkt));
        } else if (ret == GRO_ERROR) {
            rte_free(entry);
        }
    }

func_exit:
    if (ret != GRO_MERGED) {
        pkt_push(pkt, sizeof(struct vr_gro));
        rte_pktmbuf_prepend(m, sizeof(struct vr_gro));
    }
    return (ret == GRO_MERGED)?1:0;
}


