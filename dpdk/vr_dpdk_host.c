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
 * vr_dpdk_host.c -- DPDK vrouter module
 *
 */

#include "vr_dpdk.h"
#include "vr_fragment.h"
#include "vr_hash.h"
#include "vr_proto.h"
#include "vr_sandesh.h"

#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/user.h>
#include <sys/resource.h>

#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_timer.h>

/* Max number of CPUs. We adjust it later in vr_dpdk_host_init() */
unsigned int vr_num_cpus = VR_MAX_CPUS;

/* Global init flag */
static bool vr_host_inited = false;

extern void vr_malloc_stats(unsigned int, unsigned int);
extern void vr_free_stats(unsigned int);
/* RCU callback */
extern void vr_flow_defer_cb(struct vrouter *router, void *arg);


static void *
dpdk_page_alloc(unsigned int size)
{
    return rte_malloc(0, size, PAGE_SIZE);
}

static void
dpdk_page_free(void *address, unsigned int size)
{
    rte_free(address);
}

static int
dpdk_printf(const char *format, ...)
{
    va_list args;

    if (RTE_LOGTYPE_DPCORE & rte_logs.type) {
        char buf[VR_DPDK_STR_BUF_SZ] = "DPCORE: ";

        strncat(buf, format, sizeof(buf) - strlen(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        va_start(args, format);
        rte_vlog(RTE_LOG_INFO, RTE_LOGTYPE_DPCORE, buf, args);
        va_end(args);
    }

    return 0;
}

static void *
dpdk_malloc(unsigned int size, unsigned int object)
{
    void *mem = rte_malloc(NULL, size, 0);
    if (likely(mem != NULL)) {
        vr_malloc_stats(size, object);
    }

    return mem;
}

static void *
dpdk_zalloc(unsigned int size, unsigned int object)
{
    void *mem = rte_zmalloc(NULL, size, 0);
    if (likely(mem != NULL)) {
        vr_malloc_stats(size, object);
    }

    return mem;
}

static void
dpdk_free(void *mem, unsigned int object)
{
    if (mem) {
        vr_free_stats(object);
        rte_free(mem);
    }

    return;
}

static uint64_t
dpdk_vtop(void *address)
{
    /* TODO: not used */
    rte_panic("%s: not used in DPDK mode\n", __func__);

    return (uint64_t)0;
}

static struct vr_packet *
dpdk_palloc(unsigned int size)
{
    struct rte_mbuf *m;

    /* in DPDK we have fixed-sized mbufs only */
    RTE_VERIFY(size <= vr_packet_sz);
    m = rte_pktmbuf_alloc(vr_dpdk.rss_mempool);
    if (!m)
        return (NULL);

    return vr_dpdk_packet_get(m, NULL);
}

static struct vr_packet *
dpdk_palloc_head(struct vr_packet *pkt, unsigned int size)
{
    /* TODO: not implemented */
    RTE_LOG(ERR, VROUTER, "%s: not implemented\n", __func__);
    return NULL;
}

static struct vr_packet *
dpdk_pexpand_head(struct vr_packet *pkt, unsigned int hspace)
{
    /* TODO: not implemented */
    return pkt;
}

static void
dpdk_pfree(struct vr_packet *pkt, unsigned short reason)
{
    struct vrouter *router = vrouter_get(0);

    router->vr_pdrop_stats[rte_lcore_id()][reason]++;

    rte_pktmbuf_free(vr_dpdk_pkt_to_mbuf(pkt));
}

void
vr_dpdk_pfree(struct rte_mbuf *mbuf, unsigned short reason)
{
    dpdk_pfree(vr_dpdk_mbuf_to_pkt(mbuf), reason);
}


static void
dpdk_preset(struct vr_packet *pkt)
{
    struct rte_mbuf *m;

    if (!pkt)
        rte_panic("%s: NULL pkt", __func__);

    m = vr_dpdk_pkt_to_mbuf(pkt);

    /* Reset packet data */
    pkt->vp_data = rte_pktmbuf_headroom(m);
    pkt->vp_tail = rte_pktmbuf_headroom(m) + rte_pktmbuf_data_len(m);
    pkt->vp_len = rte_pktmbuf_data_len(m);

    return;
}

/**
 * Copy packet mbuf data to another packet mbuf.
*
 * @param dst
 *   The destination packet mbuf.
 * @param src
 *   The source packet mbuf.
 */

static inline void
dpdk_pktmbuf_data_copy(struct rte_mbuf *dst, struct rte_mbuf *src)
{
    dst->data_off = src->data_off;
    dst->port = src->port;
    dst->ol_flags = src->ol_flags;
    dst->packet_type = src->packet_type;
    dst->data_len = src->data_len;
    dst->pkt_len = src->pkt_len;
    dst->vlan_tci = src->vlan_tci;
    dst->hash = src->hash;
    dst->seqn = src->seqn;
    dst->userdata = src->userdata;
    dst->tx_offload = src->tx_offload;

    __rte_mbuf_sanity_check(dst, 1);
    __rte_mbuf_sanity_check(src, 0);

    /* copy data */
    rte_memcpy(rte_pktmbuf_mtod(dst, void *),
            rte_pktmbuf_mtod(src, void *), src->data_len);
}

/**
 * Creates a copy of the given packet mbuf.
 * TODO: remove once rte_pktmbuf_copy() is in DPDK
 *
 * Walks through all segments of the given packet mbuf, and for each of them:
 *  - Creates a new packet mbuf from the given pool.
 *  - Copies data to the newly created mbuf.
 * Then updates pkt_len and nb_segs of the "copy" packet mbuf to match values
 * from the original packet mbuf.
 *
 * @param md
 *   The packet mbuf to be copied.
 * @param mp
 *   The mempool from which the "copy" mbufs are allocated.
 * @return
 *   - The pointer to the new "copy" mbuf on success.
 *   - NULL if allocation fails.
 */
inline struct rte_mbuf *
vr_dpdk_pktmbuf_copy(struct rte_mbuf *md, struct rte_mempool *mp)
{
    struct rte_mbuf *mc, *mi, **prev;
    uint32_t pktlen;
    uint8_t nseg;

    if (unlikely ((mc = rte_pktmbuf_alloc(mp)) == NULL))
        return (NULL);

    mi = mc;
    prev = &mi->next;
    pktlen = md->pkt_len;
    nseg = 0;

    do {
        nseg++;
        dpdk_pktmbuf_data_copy(mi, md);
        *prev = mi;
        prev = &mi->next;
    } while ((md = md->next) != NULL &&
        (mi = rte_pktmbuf_alloc(mp)) != NULL);

    *prev = NULL;
    mc->nb_segs = nseg;
    mc->pkt_len = pktlen;

    /* Allocation of new indirect segment failed */
    if (unlikely (mi == NULL)) {
        rte_pktmbuf_free(mc);
        return (NULL);
    }

    __rte_mbuf_sanity_check(mc, 1);
    return (mc);
}

/* VRouter callback */
static struct vr_packet *
dpdk_pclone(struct vr_packet *pkt)
{
    /*
     * TODO: We have not tested pclone option on DPDK 2.0. - (mbuf leak).
     */

/* Macro RTE_VERSION is workaround, we have mbuf leak in DPDK 2.0 */
#if (RTE_VERSION >= RTE_VERSION_NUM(2, 1, 0, 0))
    struct rte_mbuf *m, *m_clone;
    struct vr_packet *pkt_clone;

    m = vr_dpdk_pkt_to_mbuf(pkt);

    m_clone = rte_pktmbuf_clone(m, vr_dpdk.rss_mempool);
    if (!m_clone)
        return NULL;

    /* clone vr_packet data */
    pkt_clone = vr_dpdk_mbuf_to_pkt(m_clone);
    *pkt_clone = *pkt;
    pkt_clone->vp_cpu = vr_get_cpu();

    return pkt_clone;
#else
    /* if no scatter/gather enabled -> just copy the mbuf */
    struct rte_mbuf *m, *m_copy;
    struct vr_packet *pkt_copy;

    m = vr_dpdk_pkt_to_mbuf(pkt);

    m_copy = vr_dpdk_pktmbuf_copy(m, vr_dpdk.rss_mempool);
    if (!m_copy)
        return NULL;

    /* copy vr_packet data */
    pkt_copy = vr_dpdk_mbuf_to_pkt(m_copy);
    *pkt_copy = *pkt;
    /* set head pointer to a copy */
    pkt_copy->vp_head = m_copy->buf_addr;

    return pkt_copy;
#endif
}

/* Copy the specified number of bytes from the source mbuf to the
 * destination buffer.
 */
static int
dpdk_pktmbuf_copy_bits(const struct rte_mbuf *mbuf, int offset,
    void *to, int len)
{
    /* how many bytes to copy in loop */
    int copy = 0;
    /* loop pointer to a source data */
    void *from;

    /* check total packet length */
    if (unlikely(offset > (int)rte_pktmbuf_pkt_len(mbuf) - len))
        goto fault;

    do {
        if (offset < rte_pktmbuf_data_len(mbuf)) {
            /* copy a piece of data */
            from = (void *)(rte_pktmbuf_mtod_offset(mbuf, uintptr_t, offset));
            copy = rte_pktmbuf_data_len(mbuf) - offset;
            if (copy > len)
                copy = len;
            rte_memcpy(to, from, copy);
            offset = 0;
        } else {
            offset -= rte_pktmbuf_data_len(mbuf);
        }
        /* get next mbuf */
        to += copy;
        len -= copy;
        mbuf = mbuf->next;
    } while (unlikely(len > 0 && NULL != mbuf));

    if (likely(0 == len))
        return 0;

fault:
    return -EFAULT;
}

/* VRouter callback */
static int
dpdk_pcopy(unsigned char *dst, struct vr_packet *p_src,
    unsigned int offset, unsigned int len)
{
    int ret;
    struct rte_mbuf *src;

    src = vr_dpdk_pkt_to_mbuf(p_src);
    ret = dpdk_pktmbuf_copy_bits(src, offset, dst, len);
    if (ret)
        return ret;

    return len;
}

static unsigned short
dpdk_pfrag_len(struct vr_packet *pkt)
{
    struct rte_mbuf *m;

    m = vr_dpdk_pkt_to_mbuf(pkt);

    return rte_pktmbuf_pkt_len(m) - rte_pktmbuf_data_len(m);
}

static unsigned short
dpdk_phead_len(struct vr_packet *pkt)
{
    struct rte_mbuf *m;

    m = vr_dpdk_pkt_to_mbuf(pkt);

    return rte_pktmbuf_data_len(m);
}

static void
dpdk_pset_data(struct vr_packet *pkt, unsigned short offset)
{
    struct rte_mbuf *m;

    m = vr_dpdk_pkt_to_mbuf(pkt);
    m->buf_addr = pkt->vp_head;
    m->data_off = offset;

    return;
}

static unsigned int
dpdk_get_cpu(void)
{
    unsigned lcore_id = rte_lcore_id();

    /* For the RCU thread we get LCORE_ID_ANY, so memory stats and
     * other functions get crashed trying to index per-cpu data.
     */
    if (lcore_id < vr_num_cpus)
        return lcore_id;
    else
        return 0;
}

/* DPDK timer callback */
static void
dpdk_timer(struct rte_timer *tim, void *arg)
{
    struct vr_timer *vtimer = (struct vr_timer*)arg;

    vtimer->vt_timer(vtimer->vt_vr_arg);
}

static int
dpdk_create_timer(struct vr_timer *vtimer)
{
    struct rte_timer *timer;
    uint64_t hz, ticks;

    timer = rte_zmalloc("vr_dpdk_timer", sizeof(struct rte_timer), 0);

    if (!timer) {
        RTE_LOG(ERR, VROUTER, "Error allocating RTE timer\n");
        return -1;
    }

    /* init timer */
    rte_timer_init(timer);
    vtimer->vt_os_arg = (void *)timer;

    /* reset timer */
    hz = rte_get_timer_hz();
    ticks = hz * vtimer->vt_msecs / 1000;
    if (rte_timer_reset(timer, ticks, PERIODICAL, VR_DPDK_TIMER_LCORE_ID,
        dpdk_timer, vtimer) == -1) {
        RTE_LOG(ERR, VROUTER, "Error resetting timer\n");
        rte_free(timer);

        return -1;
    }

    return 0;
}

static void
dpdk_delete_timer(struct vr_timer *vtimer)
{
    struct rte_timer *timer = (struct rte_timer*)vtimer->vt_os_arg;

    if (timer) {
        rte_timer_stop_sync(timer);
        rte_free(timer);
    } else {
        RTE_LOG(ERR, VROUTER, "No timer to delete\n");
    }
}

static void
dpdk_get_time(unsigned long *sec, unsigned long *usec)
{
    struct timespec ts;

    *sec = *usec = 0;
    if (-1 == clock_gettime(CLOCK_REALTIME, &ts))
        return;

    *sec = ts.tv_sec;
    *usec = ts.tv_nsec / 1000;

    return;
}

static void
dpdk_get_mono_time(unsigned int *sec, unsigned int *nsec)
{
    struct timespec ts;

    *sec = *nsec = 0;
    if (-1 == clock_gettime(CLOCK_MONOTONIC, &ts))
        return;

    *sec = ts.tv_sec;
    *nsec = ts.tv_nsec;

    return;
}

/* Work callback called on NetLink lcore */
static void
dpdk_schedule_work(unsigned int cpu, void (*fn)(void *), void *arg)
{
    /* no RCU reader lock needed, just do the work */
    fn(arg);
}

static void
dpdk_delay_op(void)
{
    synchronize_rcu();

    return;
}

/* RCU callback called on RCU thread */
static void
dpdk_rcu_cb(struct rcu_head *rh)
{
    int i;
    struct vr_dpdk_rcu_cb_data *cb_data;
    struct vr_defer_data *defer;
    struct vr_flow_queue *vfq;
    struct vr_packet_node *pnode;


    cb_data = CONTAINER_OF(rcd_rcu, struct vr_dpdk_rcu_cb_data, rh);

    /* check if we need to pass the callback to packet lcore */
    if ((cb_data->rcd_user_cb == vr_flow_defer_cb) &&
            cb_data->rcd_user_data) {
        defer = (struct vr_defer_data *)cb_data->rcd_user_data;
        vfq = ((struct vr_flow_defer_data *)defer->vdd_data)->vfdd_flow_queue;
        if (vfq) {
            for (i = 0; i < VR_MAX_FLOW_QUEUE_ENTRIES; i++) {
                pnode = &vfq->vfq_pnodes[i];
                if (pnode->pl_packet) {
                    RTE_LOG(DEBUG, VROUTER, "%s: lcore %u passing RCU callback "
                            "to lcore %u\n", __func__, rte_lcore_id(),
                            VR_DPDK_PACKET_LCORE_ID);
                    vr_dpdk_lcore_cmd_post(VR_DPDK_PACKET_LCORE_ID,
                            VR_DPDK_LCORE_RCU_CMD, (uintptr_t)rh);
                    return;
                }
            }
            RTE_LOG(DEBUG, VROUTER, "%s: lcore %u passing RCU callback to lcore %u\n",
                    __func__, rte_lcore_id(), VR_DPDK_PACKET_LCORE_ID);
        }
    }
    /* no need to send any packets, so just call the callback */
    cb_data->rcd_user_cb(cb_data->rcd_router, cb_data->rcd_user_data);
    vr_free(cb_data, VR_DEFER_OBJECT);
}

static void
dpdk_defer(struct vrouter *router, vr_defer_cb user_cb, void *data)
{
    struct vr_dpdk_rcu_cb_data *cb_data;

    cb_data = CONTAINER_OF(rcd_user_data, struct vr_dpdk_rcu_cb_data, data);
    cb_data->rcd_user_cb = user_cb;
    cb_data->rcd_router = router;
    call_rcu(&cb_data->rcd_rcu, dpdk_rcu_cb);
}

static void *
dpdk_get_defer_data(unsigned int len)
{
    struct vr_dpdk_rcu_cb_data *cb_data;

    if (!len)
        return NULL;

    cb_data = dpdk_malloc(sizeof(*cb_data) + len, VR_DEFER_OBJECT);
    if (!cb_data) {
        return NULL;
    }

    return cb_data->rcd_user_data;
}

static void
dpdk_put_defer_data(void *data)
{
    struct vr_dpdk_rcu_cb_data *cb_data;

    if (!data)
        return;

    cb_data = CONTAINER_OF(rcd_user_data, struct vr_dpdk_rcu_cb_data, data);
    dpdk_free(cb_data, VR_DEFER_OBJECT);

    return;
}

static void *
dpdk_network_header(struct vr_packet *pkt)
{
    if (pkt->vp_network_h < pkt->vp_end)
        return pkt->vp_head + pkt->vp_network_h;

    /* TODO: for buffer chain? */
    rte_panic("%s: buffer chain not supported\n", __func__);

    return NULL;
}

static void *
dpdk_inner_network_header(struct vr_packet *pkt)
{
    /* TODO: not used? */
    rte_panic("%s: not implemented\n", __func__);

    return NULL;
}

static void *
dpdk_data_at_offset(struct vr_packet *pkt, unsigned short off)
{
    if (off < pkt->vp_end)
        return pkt->vp_head + off;

    /* TODO: for buffer chain? */
    rte_panic("%s: buffer chain not supported\n", __func__);

    return NULL;
}

/*
 * dpdk_pheader_pointer
 * return pointer to data at pkt->vp_data offset if hdr_len bytes
 * in continuous memory, otherwise copy data to buf
 */
static void *
dpdk_pheader_pointer(struct vr_packet *pkt, unsigned short hdr_len, void *buf)
{
    struct rte_mbuf *m;
    int offset;

    m = vr_dpdk_pkt_to_mbuf(pkt);

    /*
     * vp_data is offset from start of buffer,
     * so first calculate offset from start of mbuf payload
     */
    offset = pkt->vp_data - rte_pktmbuf_headroom(m);
    if ((offset + hdr_len) < rte_pktmbuf_data_len(m))
        return (void *)((uintptr_t)m->buf_addr + pkt->vp_data);
    else {
        int len = rte_pktmbuf_data_len(m) - offset;
        void *tmp_buf = buf;

        rte_memcpy(tmp_buf, rte_pktmbuf_mtod_offset(m, char *, offset), len);
        hdr_len -= len;
        tmp_buf = (void *)((uintptr_t)tmp_buf + len);

        /* iterate thru buffers chain */
        while (hdr_len) {
            m = m->next;
            if (!m)
                return (NULL);
            if (hdr_len > rte_pktmbuf_data_len(m))
                len = rte_pktmbuf_data_len(m);
            else
                len = hdr_len;

            rte_memcpy(tmp_buf, rte_pktmbuf_mtod(m, void *), len);

            tmp_buf = (void *)((uintptr_t)tmp_buf + len);
            hdr_len -= len;
        }

        return (buf);
    }
}

/* VRouter callback */
static int
dpdk_pcow(struct vr_packet *pkt, unsigned short head_room)
{
    struct rte_mbuf *mbuf = vr_dpdk_pkt_to_mbuf(pkt);

    if (head_room > rte_pktmbuf_headroom(mbuf)) {
        return -ENOMEM;
    }

    return 0;
}

/*
 * dpdk_get_udp_src_port - return a source port for the outer UDP header.
 * The source port is based on a hash of the inner IP source/dest addresses,
 * vrf (and inner TCP/UDP ports in the future). The label from fmd
 * will be used in the future to detect whether it is a L2/L3 packet.
 * Returns 0 on error, valid source port otherwise.
 *
 * Based on linux/vrouter_mod.c:lh_get_udp_src_port
 * Copyright (c) 2013, 2014 Juniper Networks, Inc.
 */
static uint16_t
dpdk_get_udp_src_port(struct vr_packet *pkt, struct vr_forwarding_md *fmd,
    unsigned short vrf)
{
    struct rte_mbuf *mbuf = vr_dpdk_pkt_to_mbuf(pkt);
    unsigned int pull_len;
    uint32_t ip_src, ip_dst, hashval, port_range;
    struct vr_ip *iph;
    uint16_t port;
    uint16_t sport = 0, dport = 0;
    struct vr_fragment *frag;
    struct vrouter *router = vrouter_get(0);
    uint32_t hash_key[5];
    uint16_t *l4_hdr;
    struct vr_flow_entry *fentry;

    if (likely(mbuf->ol_flags & PKT_RX_RSS_HASH)) {
        hashval = mbuf->hash.rss;
    } else {
        if (unlikely(hashrnd_inited == 0)) {
            vr_hashrnd = random();
            hashrnd_inited = 1;
        }

        if (pkt->vp_type == VP_TYPE_IP) {
            /* Ideally the below code is only for VP_TYPE_IP and not
             * for IP6. But having explicit check for IP only break IP6
             */
            pull_len = sizeof(struct iphdr);
            pull_len += pkt_get_network_header_off(pkt);
            pull_len -= rte_pktmbuf_headroom(mbuf);

            /* It's safe to assume the ip hdr is within this mbuf, so we skip
             * all the header checks.
             */

            iph = (struct vr_ip *)(mbuf->buf_addr + pkt_get_network_header_off(pkt));
            if (vr_ip_transport_header_valid(iph)) {
                if ((iph->ip_proto == VR_IP_PROTO_TCP) ||
                            (iph->ip_proto == VR_IP_PROTO_UDP)) {
                    l4_hdr = (__u16 *) (((char *) iph) + (iph->ip_hl * 4));
                    sport = *l4_hdr;
                    dport = *(l4_hdr+1);
                }
            } else {
                /*
                 * If this fragment required flow lookup, get the source and
                 * dst port from the frag entry. Otherwise, use 0 as the source
                 * dst port (which could result in fragments getting a different
                 * outer UDP source port than non-fragments in the same flow).
                 */
                frag = vr_fragment_get(router, vrf, iph);
                if (frag) {
                    sport = frag->f_sport;
                    dport = frag->f_dport;
                }
            }

            if (fmd && fmd->fmd_flow_index >= 0) {
                fentry = vr_flow_get_entry(router, fmd->fmd_flow_index);
                if (fentry) {
                    vr_dpdk_mbuf_reset(pkt);
                    return fentry->fe_udp_src_port;
                }
            }

            ip_src = iph->ip_saddr;
            ip_dst = iph->ip_daddr;

            hash_key[0] = ip_src;
            hash_key[1] = ip_dst;
            hash_key[2] = vrf;
            hash_key[3] = sport;
            hash_key[4] = dport;

            hashval = rte_jhash(hash_key, 20, vr_hashrnd);
            vr_dpdk_mbuf_reset(pkt);
        } else {

            /* We treat all non-ip packets as L2 here. For V6 we can extract
             * the required fieleds explicity and manipulate the src port
             */

            if (pkt_head_len(pkt) < ETH_HLEN)
                goto error;

            hashval = vr_hash(pkt_data(pkt), ETH_HLEN, vr_hashrnd);
            /* Include the VRF to calculate the hash */
            hashval = vr_hash_2words(hashval, vrf, vr_hashrnd);
        }
    } /* !PKT_RX_RSS_HASH */


    /*
     * Convert the hash value to a value in the port range that we want
     * for dynamic UDP ports
     */
    port_range = VR_MUDP_PORT_RANGE_END - VR_MUDP_PORT_RANGE_START;
    port = (uint16_t) (((uint64_t) hashval * port_range) >> 32);

    if (unlikely(port > port_range)) {
        /*
         * Shouldn't happen...
         */
        port = 0;
    }

    return (port + VR_MUDP_PORT_RANGE_START);

error:
    vr_dpdk_mbuf_reset(pkt);
    return 0;
}

/**
 * dpdk_adjust_tcp_mss - helper adjusting TCP Maximum Segment Size, used in
 * dpdk_pkt_from_vm_tcp_mss_adj vRouter callback for packets from the VM and in
 * vr_ip_transport_parse to perform MSS adjust for packets sent to the VM.
 */
void
dpdk_adjust_tcp_mss(struct tcphdr *tcph, unsigned short overlay_len,
                    unsigned char iph_len)
{
    int opt_off = sizeof(struct tcphdr);
    u_int8_t *opt_ptr = (u_int8_t *) tcph;
    u_int16_t pkt_mss, max_mss, mtu;
    unsigned int csum;
    uint8_t port_id;
    struct vrouter *router = vrouter_get(0);

    if ((tcph == NULL) || !(tcph->syn) || (router == NULL))
        return;

    if (router->vr_eth_if == NULL)
        return;

    while (opt_off < (tcph->doff * 4)) {
        switch (opt_ptr[opt_off]) {
        case TCPOPT_EOL:
            return;

        case TCPOPT_NOP:
            opt_off++;
            continue;

        case TCPOPT_MAXSEG:
            if ((opt_off + TCPOLEN_MAXSEG) > (tcph->doff*4))
                return;

            if (opt_ptr[opt_off+1] != TCPOLEN_MAXSEG)
                return;

            pkt_mss = (opt_ptr[opt_off+2] << 8) | opt_ptr[opt_off+3];
            if (router->vr_eth_if == NULL)
                return;

            port_id = (((struct vr_dpdk_ethdev *)(router->vr_eth_if->vif_os))->
                    ethdev_port_id);
            rte_eth_dev_get_mtu(port_id, &mtu);

            max_mss = mtu - (overlay_len + iph_len + sizeof(struct tcphdr));

            if (pkt_mss > max_mss) {
                opt_ptr[opt_off+2] = (max_mss & 0xff00) >> 8;
                opt_ptr[opt_off+3] = max_mss & 0xff;

                /* Recalculate checksum */
                csum = (unsigned short)(~rte_cpu_to_be_16(tcph->check));
                csum = csum + (unsigned short)~pkt_mss;
                csum = (csum & 0xffff) + (csum >> 16);
                csum += max_mss;
                csum = (csum & 0xffff) + (csum >> 16);
                tcph->check = rte_cpu_to_be_16(~((unsigned short)csum));
            }
            return;

        default:
            if ((opt_off + 1) == (tcph->doff*4))
                return;

            if (opt_ptr[opt_off+1])
                opt_off += opt_ptr[opt_off+1];
            else
                opt_off++;

            continue;
        } /* switch */
    } /* while */

    return;
}

/*
 * dpdk_pkt_from_vm_tcp_mss_adj - perform TCP MSS adjust, if required, for packets
 * that are sent by a VM. Returns 0 on success, non-zero otherwise.
 */
static int
dpdk_pkt_from_vm_tcp_mss_adj(struct vr_packet *pkt, unsigned short overlay_len)
{
    struct rte_mbuf *m = vr_dpdk_pkt_to_mbuf(pkt);
    struct vr_ip *ip4h = NULL;
    struct vr_ip6 *ip6h = NULL;
    struct tcphdr *tcph;
    int offset;
    unsigned char iph_len = 0, iph_proto = 0;

    /* check if whole ip header is in the packet */
    if (pkt->vp_type == VP_TYPE_IP) {
        offset = sizeof(struct vr_ip);
        if (pkt->vp_data + offset < pkt->vp_end)
            ip4h = (struct vr_ip *) ((uintptr_t)m->buf_addr + pkt->vp_data);
        else
            rte_panic("%s: ip header not in first buffer\n", __func__);
        iph_proto = ip4h->ip_proto;
        iph_len = ip4h->ip_hl * 4;

        /*
         * If this is a fragment and not the first one, it can be ignored
         */
        if (ip4h->ip_frag_off & rte_cpu_to_be_16(IP_OFFMASK))
            goto out;
    } else if (pkt->vp_type == VP_TYPE_IP6) {
        iph_len = offset = sizeof(struct vr_ip6);
        if (pkt->vp_data + offset < pkt->vp_end)
            ip6h = (struct vr_ip6 *) ((uintptr_t)m->buf_addr + pkt->vp_data);
        else
            rte_panic("%s: ip header not in first buffer\n", __func__);
        iph_proto = ip6h->ip6_nxt;
    }

    if (iph_proto != VR_IP_PROTO_TCP)
        goto out;

    /*
     * Now we know exact ip header length,
     * check if whole tcp header is also in the packet
     */
    offset = iph_len + sizeof(struct tcphdr);

    if (pkt->vp_data + offset < pkt->vp_end)
        tcph = (struct tcphdr *)pkt_data_at_offset(pkt, pkt->vp_data + iph_len);
    else
        rte_panic("%s: tcp header not in first buffer\n", __func__);

    if ((tcph->doff << 2) <= (sizeof(struct tcphdr))) {
        /*Nothing to do if there are no TCP options */
        goto out;
    }


    offset += (tcph->doff << 2) - sizeof(struct tcphdr);
    if (pkt->vp_data + offset > pkt->vp_end)
        rte_panic("%s: tcp header outside first buffer\n", __func__);


    dpdk_adjust_tcp_mss(tcph, overlay_len, iph_len);

out:
    return 0;
}

static unsigned int
dpdk_pgso_size(struct vr_packet *pkt)
{
    /* TODO: not implemented */
    return 0;
}

static void
dpdk_add_mpls(struct vrouter *router, unsigned mpls_label)
{
    int ret, i;
    struct vr_interface *eth_vif;

    for (i = 0; i < router->vr_max_interfaces; i++) {
        eth_vif = __vrouter_get_interface(router, i);
        if (eth_vif && (eth_vif->vif_type == VIF_TYPE_PHYSICAL)
            && (eth_vif->vif_flags & VIF_FLAG_FILTERING_OFFLOAD)) {
            RTE_LOG(INFO, VROUTER, "Enabling hardware acceleration on vif %u for MPLS %u\n",
                (unsigned)eth_vif->vif_idx, mpls_label);
            if (!eth_vif->vif_ip) {
                RTE_LOG(ERR, VROUTER, "    error accelerating MPLS %u: no IP address set\n",
                    mpls_label);
                continue;
            }
            ret = vr_dpdk_lcore_mpls_schedule(eth_vif, eth_vif->vif_ip, mpls_label);
            if (ret != 0)
                RTE_LOG(INFO, VROUTER, "    error accelerating MPLS %u: %s (%d)\n",
                    mpls_label, rte_strerror(-ret), -ret);
        }
    }

}

static void
dpdk_del_mpls(struct vrouter *router, unsigned mpls_label)
{
    /* TODO: not implemented */
}

static int
dpdk_pkt_may_pull(struct vr_packet *pkt, unsigned int len)
{
    struct rte_mbuf *mbuf = vr_dpdk_pkt_to_mbuf(pkt);

    if (len > rte_pktmbuf_data_len(mbuf))
        return -1;

    vr_dpdk_mbuf_reset(pkt);
    return 0;
}

static void
dpdk_set_log_level(unsigned int log_level)
{
    unsigned int level;

    switch(log_level) {
    case VR_LOG_EMERG:
        level = RTE_LOG_EMERG;
        break;

    case VR_LOG_ALERT:
        level = RTE_LOG_ALERT;
        break;

    case VR_LOG_CRIT:
        level = RTE_LOG_CRIT;
        break;

    case VR_LOG_ERR:
        level = RTE_LOG_ERR;
        break;

    case VR_LOG_WARNING:
        level = RTE_LOG_WARNING;
        break;

    case VR_LOG_NOTICE:
        level = RTE_LOG_NOTICE;
        break;

    case VR_LOG_INFO:
        level = RTE_LOG_INFO;
        break;

    case VR_LOG_DEBUG:
        level = RTE_LOG_DEBUG;
        break;

    default:
        level = 0;
        break;
    }

    if (level > 0)
        rte_set_log_level(level);
    else
        RTE_LOG(ERR, VROUTER, "Error: wrong log level (%u) specified\n",
                level);
}

static unsigned int
dpdk_get_log_level(void)
{
    unsigned int level = rte_get_log_level();

    switch(level) {
    case RTE_LOG_EMERG:
        return VR_LOG_EMERG;

    case RTE_LOG_ALERT:
        return VR_LOG_ALERT;

    case RTE_LOG_CRIT:
        return VR_LOG_CRIT;

    case RTE_LOG_ERR:
        return VR_LOG_ERR;

    case RTE_LOG_WARNING:
        return VR_LOG_WARNING;

    case RTE_LOG_NOTICE:
        return VR_LOG_NOTICE;

    case RTE_LOG_INFO:
        return VR_LOG_INFO;

    case RTE_LOG_DEBUG:
        return VR_LOG_DEBUG;
    }

    /* Should never reach here */
    return 0;
}

static void
dpdk_set_log_type(unsigned int log_type, int enable)
{
    unsigned int type;

    switch (log_type) {
    case VR_LOGTYPE_VROUTER:
        type = RTE_LOGTYPE_VROUTER;
        break;

    case VR_LOGTYPE_USOCK:
        type = RTE_LOGTYPE_USOCK;
        break;

    case VR_LOGTYPE_UVHOST:
        type = RTE_LOGTYPE_UVHOST;
        break;

    case VR_LOGTYPE_DPCORE:
        type = RTE_LOGTYPE_DPCORE;
        break;

    default:
        type = 0;
        break;
    }

    if (type > 0)
        rte_set_log_type(type, enable);
    else
        RTE_LOG(ERR, VROUTER, "Error: wrong log type (0x%x) specified\n",
                type);
}

static unsigned int
dpdk_log_type_to_vr_type(unsigned int type)
{
    switch (type) {
    case RTE_LOGTYPE_VROUTER:
        return VR_LOGTYPE_VROUTER;

    case RTE_LOGTYPE_USOCK:
        return VR_LOGTYPE_USOCK;

    case RTE_LOGTYPE_UVHOST:
        return VR_LOGTYPE_UVHOST;

    case RTE_LOGTYPE_DPCORE:
        return VR_LOGTYPE_DPCORE;
    }

    /* Should never reach here */
    return 0;
}

static unsigned int *
dpdk_get_enabled_log_types(int *size)
{
    unsigned int enabled_flags = rte_get_log_type() & ~(RTE_LOGTYPE_USER1 - 1);

    /* Count number of enabled types (set bits in a number) */
    int num = __builtin_popcount(enabled_flags);

    unsigned int *enabled_array =
            vr_malloc(sizeof(int) * num, VR_LOG_TYPES_OBJECT);
    int i;
    unsigned int shift = 1;

    for (i = 0; i < num; shift <<= 1) {
        if (enabled_flags & shift) {
            enabled_array[i++] = dpdk_log_type_to_vr_type(shift);
        }
    }

    *size = i;
    return enabled_array;
}

static void
dpdk_soft_reset(struct vrouter *router)
{
    rcu_barrier();
}

static int
dpdk_is_frag_limit_exceeded(void)
{
    struct vrouter *router = vrouter_get(0);
    struct vr_malloc_stats *stats;
    uint64_t sum = 0;
    unsigned int cpu;

    if (router->vr_malloc_stats) {
        for (cpu = 0; cpu < vr_num_cpus; cpu++) {
            if (router->vr_malloc_stats[cpu]) {
                stats = &router->vr_malloc_stats[cpu][VR_FRAGMENT_QUEUE_ELEMENT_OBJECT];
                sum += stats->ms_alloc;
                sum -= stats->ms_free;
            }
        }
        if (sum > VR_DPDK_MAX_FRAGMENT_ELEMENTS)
            return 1;
    }

    return 0;
}

struct host_os dpdk_host = {
    .hos_printf                     =    dpdk_printf,
    .hos_malloc                     =    dpdk_malloc,
    .hos_zalloc                     =    dpdk_zalloc,
    .hos_free                       =    dpdk_free,
    .hos_vtop                       =    dpdk_vtop, /* not used */
    .hos_page_alloc                 =    dpdk_page_alloc,
    .hos_page_free                  =    dpdk_page_free,

    .hos_palloc                     =    dpdk_palloc,
    .hos_palloc_head                =    dpdk_palloc_head, /* not implemented */
    .hos_pexpand_head               =    dpdk_pexpand_head, /* not implemented */
    .hos_pfree                      =    dpdk_pfree,
    .hos_preset                     =    dpdk_preset,
    .hos_pclone                     =    dpdk_pclone,
    .hos_pcopy                      =    dpdk_pcopy,
    .hos_pfrag_len                  =    dpdk_pfrag_len,
    .hos_phead_len                  =    dpdk_phead_len,
    .hos_pset_data                  =    dpdk_pset_data,
    .hos_pgso_size                  =    dpdk_pgso_size, /* not implemented, returns 0 */

    .hos_get_cpu                    =    dpdk_get_cpu,
    .hos_schedule_work              =    dpdk_schedule_work,
    .hos_delay_op                   =    dpdk_delay_op, /* do nothing */
    .hos_defer                      =    dpdk_defer,
    .hos_get_defer_data             =    dpdk_get_defer_data,
    .hos_put_defer_data             =    dpdk_put_defer_data,
    .hos_get_time                   =    dpdk_get_time,
    .hos_get_mono_time              =    dpdk_get_mono_time,
    .hos_create_timer               =    dpdk_create_timer,
    .hos_delete_timer               =    dpdk_delete_timer,

    .hos_network_header             =    dpdk_network_header, /* for chains? */
    .hos_inner_network_header       =    dpdk_inner_network_header, /* not used? */
    .hos_data_at_offset             =    dpdk_data_at_offset, /* for chains? */
    .hos_pheader_pointer            =    dpdk_pheader_pointer,
    .hos_pull_inner_headers         =    NULL,  /* not necessary */
    .hos_pcow                       =    dpdk_pcow,
    .hos_pull_inner_headers_fast    =    NULL,  /* not necessary */
#if VR_DPDK_USE_MPLS_UDP_ECMP
    .hos_get_udp_src_port           =    dpdk_get_udp_src_port,
#endif
    .hos_pkt_from_vm_tcp_mss_adj    =    dpdk_pkt_from_vm_tcp_mss_adj,
    .hos_pkt_may_pull               =    dpdk_pkt_may_pull,

    .hos_add_mpls                   =    dpdk_add_mpls,
    .hos_del_mpls                   =    dpdk_del_mpls, /* not implemented */
    .hos_enqueue_to_assembler       =    dpdk_fragment_assembler_enqueue,
    .hos_set_log_level              =    dpdk_set_log_level,
    .hos_set_log_type               =    dpdk_set_log_type,
    .hos_get_log_level              =    dpdk_get_log_level,
    .hos_get_enabled_log_types      =    dpdk_get_enabled_log_types,
    .hos_soft_reset                 =    dpdk_soft_reset,
    .hos_is_frag_limit_exceeded     =    dpdk_is_frag_limit_exceeded,
};

struct host_os *
vrouter_get_host(void)
{
    return &dpdk_host;
}

/* Remove xconnect callback */
void
vhost_remove_xconnect(void)
{
    int i;
    struct vr_interface *vif;
    struct vrouter *router = vrouter_get(0);

    for (i = 0; i < router->vr_max_interfaces; i++) {
        vif = __vrouter_get_interface(router, i);
        if (vif && (vif_is_vhost(vif))) {
            vif_remove_xconnect(vif);
            if (vif->vif_bridge != NULL)
                vif_remove_xconnect(vif->vif_bridge);
        }
    }
}

/* Implementation of the Linux kernel function */
void
get_random_bytes(void *buf, int nbytes)
{
    int i;

    if (nbytes == sizeof(uint32_t)) {
        *(uint32_t *)buf = (uint32_t)rte_rand();
    } else if (nbytes == sizeof(uint64_t)) {
        *(uint64_t *)buf = rte_rand();
    } else {
        for (i = 0; i < nbytes; i++) {
            *((uint8_t *)buf + i) = (uint8_t)rte_rand();
        }
    }
}

uint32_t
jhash(void *key, uint32_t length, uint32_t initval)
{
    return rte_jhash(key, length, initval);
}



/**
 * vr_dpdk_packet_get - convert DPDK mbuf to dp-core vr_packet
 * Based on linux_get_packet()
 *
 * Return vr_packet pointer.
 */
struct vr_packet *
vr_dpdk_packet_get(struct rte_mbuf *m, struct vr_interface *vif)
{
    struct vr_packet *pkt = vr_dpdk_mbuf_to_pkt(m);
    pkt->vp_cpu = rte_lcore_id();
    pkt->vp_head = m->buf_addr;

    pkt->vp_tail = rte_pktmbuf_headroom(m) + rte_pktmbuf_data_len(m);
    pkt->vp_data = rte_pktmbuf_headroom(m);
    /* vp_end is set in vr_dpdk_pktmbuf_init() */

    pkt->vp_len = rte_pktmbuf_data_len(m);
    pkt->vp_if = vif;
    pkt->vp_network_h = pkt->vp_inner_network_h = 0;
    pkt->vp_nh = NULL;
    pkt->vp_flags = 0;
    if (likely(m->ol_flags & PKT_RX_IP_CKSUM_BAD))
        pkt->vp_flags |= VP_FLAG_CSUM_PARTIAL;

    pkt->vp_ttl = 64;
    pkt->vp_type = VP_TYPE_NULL;
    pkt->vp_queue = 0;
    pkt->vp_priority = VP_PRIORITY_INVALID;

    return pkt;
}

/* Exit vRouter */
void
vr_dpdk_host_exit(void)
{
    vr_sandesh_exit();
    vrouter_exit(false);

    return;
}

/*
 * vr_dpdk_set_fd_limit - set the max number of open files for the process. The
 * user space vhost server requires one socket per interface. Allow a few more than
 * that.
 *
 * Returns 0 on success, -1 otherwise.
 */
static int
vr_dpdk_set_fd_limit(void)
{
    struct rlimit rl;
    int ret, old_cur;

    ret = getrlimit(RLIMIT_NOFILE, &rl);
    if (ret != 0) {
        RTE_LOG(ERR, VROUTER,
            "Could not get resource limits, error %d\n", errno);
        return -1;
    }

    old_cur = (int) rl.rlim_cur;
    if (rl.rlim_max < (VR_MAX_INTERFACES + VR_DPDK_NUM_FDS)) {
        rl.rlim_cur = rl.rlim_max;
    } else {
        rl.rlim_cur = VR_MAX_INTERFACES + VR_DPDK_NUM_FDS;
    }

    ret = setrlimit(RLIMIT_NOFILE, &rl);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "Could not set fd limit to %d (max %d), error %d\n",
                (int) rl.rlim_cur, (int) rl.rlim_max, errno);
        return -1;
    }

    RTE_LOG(INFO, VROUTER,
        "set fd limit to %d (prev %d, max %d)\n",
        (int) rl.rlim_cur, old_cur, (int) rl.rlim_max);

    return 0;
}


/* Init vRouter */
int
vr_dpdk_host_init(void)
{
    int ret;
    unsigned lcore_id;

    if (vr_host_inited)
        return 0;

    /*
     * Set number of CPUs. Note it is not just number of lcores, so we
     * cannot just use rte_lcore_count() here.
     */
    vr_num_cpus = 0;
    RTE_LCORE_FOREACH(lcore_id) {
        vr_num_cpus = RTE_MAX(vr_num_cpus, lcore_id);
    }
    vr_num_cpus++;

    if (!vrouter_host) {
        vrouter_host = vrouter_get_host();
        if (vr_dpdk_flow_init()) {
            return -1;
        }
    }

    /*
     * Turn off GRO/GSO as they are not implemented with DPDK.
     */
    vr_perfr = vr_perfs = 0;

    /*
     * Allow at least one file descriptor per interface (as required by the
     * user space vhost server.
     */
    ret = vr_dpdk_set_fd_limit();
    if (ret) {
        return ret;
    }

    ret = vrouter_init();
    if (ret)
        return ret;

    ret = vr_sandesh_init();
    if (ret)
        goto init_fail;

    vr_host_inited = true;

    return 0;

init_fail:
    vr_dpdk_host_exit();
    return ret;
}

/* Retry socket connection */
int
vr_dpdk_retry_connect(int sockfd, const struct sockaddr *addr,
                        socklen_t alen)
{
    int nsec;

    for (nsec = 1; nsec < VR_DPDK_RETRY_CONNECT_SECS; nsec <<= 1) {
        if (connect(sockfd, addr, alen) == 0)
            return 0;

        if (nsec < VR_DPDK_RETRY_CONNECT_SECS/2) {
            sleep(nsec);
            RTE_LOG(INFO, VROUTER, "Retrying connection for socket %d...\n",
                    sockfd);
        }
    }

    return -1;
}

/* Returns a string hash */
static inline uint32_t
dpdk_strhash(const char *k, uint32_t initval)
{
    uint32_t a, b, c;

    a = b = RTE_JHASH_GOLDEN_RATIO;
    c = initval;

    do {
        if (*k) {
            a += k[0];
            k++;
        }
        if (*k) {
            b += k[0];
            k++;
        }
        if (*k) {
            c += k[0];
            k++;
        }
        __rte_jhash_mix(a, b, c);
    } while (*k);

    return c;
}

/* Generates unique log message */
int vr_dpdk_ulog(uint32_t level, uint32_t logtype, uint32_t *last_hash,
                    const char *format, ...)
{
    va_list ap;
    int ret = 0;
    uint32_t hash;
    char buf[VR_DPDK_STR_BUF_SZ];

    /* fallback to rte_log */
    if (last_hash == NULL) {
        va_start(ap, format);
        ret = rte_log(level, logtype, "%s", buf);
        va_end(ap);
    } else {
        /* calculate message hash */
        va_start(ap, format);
        vsnprintf(buf, sizeof(buf) - 1, format, ap);
        va_end(ap);
        buf[sizeof(buf) - 1] = '\0';
        hash = dpdk_strhash(buf, level + logtype);

        if (hash != *last_hash) {
            *last_hash = hash;
            ret = rte_log(level, logtype, "%s", buf);
        }
    }

    return ret;
}

