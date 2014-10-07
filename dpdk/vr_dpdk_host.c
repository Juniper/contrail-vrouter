/*
 * Copyright (C) 2014 Semihalf.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * vr_dpdk_host.c -- DPDK vrouter module
 *
 */

#include <sys/user.h>
#include <linux/if_ether.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <rte_config.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_timer.h>
#include <rte_cycles.h>

#include "vr_dpdk.h"
#include "vr_sandesh.h"
#include "vr_proto.h"

uint32_t vr_hashrnd = 0;
int hashrnd_inited = 0;
extern int dpdk_netlink_core_id, dpdk_packet_core_id;
/* Max number of CPU */
unsigned int vr_num_cpus = RTE_MAX_LCORE;
/* Global init flag */
static bool vr_host_inited = false;


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

static void *
dpdk_malloc(unsigned int size)
{
    return rte_malloc(NULL, size, 0);
}

static void *
dpdk_zalloc(unsigned int size)
{
    return rte_calloc(NULL, size, 1, 0);
}

static void
dpdk_free(void *mem)
{
    rte_free(mem);
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
    RTE_VERIFY(size < VR_DPDK_MAX_PACKET_SZ);
    m = rte_pktmbuf_alloc(vr_dpdk.pktmbuf_pool);
    if (!m)
        return (NULL);

    return vr_dpdk_packet_get(m, NULL);
}

static struct vr_packet *
dpdk_palloc_head(struct vr_packet *pkt, unsigned int size)
{
    /* TODO: not implemented */
    fprintf(stderr, "%s: not implemented\n", __func__);
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
    struct rte_mbuf *m;

    if (!pkt)
        rte_panic("Null packet");

    /* Fetch original mbuf from packet structure */
    m = vr_dpdk_pkt_to_mbuf(pkt);

    /* TODO: implement drop stats */

    rte_pktmbuf_free(m);
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
dpdk_pktmbuf_copy_data(struct rte_mbuf *dst, struct rte_mbuf *src)
{
    dst->buf_physaddr = src->buf_physaddr;
    dst->buf_len = src->buf_len;
    dst->ol_flags = src->ol_flags;

    dst->pkt.next = NULL;
    dst->pkt.data_len = src->pkt.data_len;
    dst->pkt.nb_segs = 1;
    dst->pkt.in_port = src->pkt.in_port;
    dst->pkt.pkt_len = src->pkt.data_len;
    dst->pkt.vlan_macip = src->pkt.vlan_macip;
    dst->pkt.hash = src->pkt.hash;

    __rte_mbuf_sanity_check(dst, RTE_MBUF_PKT, 1);
    __rte_mbuf_sanity_check(src, RTE_MBUF_PKT, 0);

    /* copy data */
    rte_memcpy(dst->pkt.data, src->pkt.data, src->pkt.data_len);
}

/**
 * Creates a copy of the given packet mbuf.
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
static inline struct rte_mbuf *
dpdk_pktmbuf_copy(struct rte_mbuf *md,
        struct rte_mempool *mp)
{
    struct rte_mbuf *mc, *mi, **prev;
    uint32_t pktlen;
    uint8_t nseg;

    if (unlikely ((mc = rte_pktmbuf_alloc(mp)) == NULL))
        return (NULL);

    mi = mc;
    prev = &mi->pkt.next;
    pktlen = md->pkt.pkt_len;
    nseg = 0;

    do {
        nseg++;
        dpdk_pktmbuf_copy_data(mi, md);
        *prev = mi;
        prev = &mi->pkt.next;
    } while ((md = md->pkt.next) != NULL &&
        (mi = rte_pktmbuf_alloc(mp)) != NULL);

    *prev = NULL;
    mc->pkt.nb_segs = nseg;
    mc->pkt.pkt_len = pktlen;

    /* Allocation of new indirect segment failed */
    if (unlikely (mi == NULL)) {
        rte_pktmbuf_free(mc);
        return (NULL);
    }

    __rte_mbuf_sanity_check(mc, RTE_MBUF_PKT, 1);
    return (mc);
}

/* VRouter callback */
static struct vr_packet *
dpdk_pclone(struct vr_packet *pkt)
{
#ifdef RTE_MBUF_SCATTER_GATHER
    struct rte_mbuf *m, *m_clone;
    struct vr_packet *pkt_clone;

    m = vr_dpdk_pkt_to_mbuf(pkt);

    m_clone = rte_pktmbuf_clone(m, vr_dpdk.pktmbuf_pool);
    if (!m_clone)
        return NULL;

    /* clone vr_packet data */
    pkt_clone = vr_dpdk_mbuf_to_pkt(m_clone);
    rte_memcpy(pkt_clone, pkt, sizeof(struct vr_packet));

    return (pkt_clone);
#else
    /* if no scatter/gather enabled -> just copy the mbuf */
    struct rte_mbuf *m, *m_copy;
    struct vr_packet *pkt_copy;

    m = vr_dpdk_pkt_to_mbuf(pkt);

    m_copy = dpdk_pktmbuf_copy(m, vr_dpdk.pktmbuf_pool);
    if (!m_copy)
        return NULL;

    /* copy vr_packet data */
    pkt_copy = vr_dpdk_mbuf_to_pkt(m_copy);
    rte_memcpy(pkt_copy, pkt, sizeof(struct vr_packet));
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
            from = (void *)(rte_pktmbuf_mtod(mbuf, uintptr_t) + offset);
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
        mbuf = mbuf->pkt.next;
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
    m->pkt.data = pkt->vp_head + offset;

    return;
}

static unsigned int
dpdk_get_cpu(void)
{
    return rte_lcore_id();
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
dpdk_get_time(unsigned int *sec, unsigned int *nsec)
{
    struct timespec ts;

    *sec = *nsec = 0;
    if (-1 == clock_gettime(CLOCK_REALTIME, &ts))
        return;

    *sec = ts.tv_sec;
    *nsec = ts.tv_nsec;

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

static void
dpdk_schedule_work(unsigned int cpu, void (*fn)(void *), void *arg)
{
    /* TODO: not implemented */
    return;
}

static void
dpdk_delay_op(void)
{
    /* there is no synchronization function, so we just do nothing */
    return;
}

static void
dpdk_defer(struct vrouter *router, vr_defer_cb user_cb, void *data)
{
    /* TODO: for mirroring? */
    rte_panic("%s: not implemented\n", __func__);

    return;
}

static void *
dpdk_get_defer_data(unsigned int len)
{
    /* TODO: for mirroring? */
    rte_panic("%s: not implemented\n", __func__);

    return NULL;
}

static void
dpdk_put_defer_data(void *data)
{
    /* TODO: for mirroring? */
    rte_panic("%s: not implemented\n", __func__);

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

        rte_memcpy(tmp_buf, rte_pktmbuf_mtod(m, char *) + offset, len);
        hdr_len -= len;
        tmp_buf = (void *)((uintptr_t)tmp_buf + len);

        /* iterate thru buffers chain */
        while (hdr_len) {
            m = m->pkt.next;
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

    /* Store the right values to mbuf */
    mbuf->pkt.data = pkt_data(pkt);
    mbuf->pkt.pkt_len = pkt_len(pkt);
    mbuf->pkt.data_len = pkt_head_len(pkt);

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
 */
static uint16_t
dpdk_get_udp_src_port(struct vr_packet *pkt, struct vr_forwarding_md *fmd,
    unsigned short vrf)
{
    struct rte_mbuf *mbuf = vr_dpdk_pkt_to_mbuf(pkt);
    unsigned int pull_len;
    uint32_t ip_src, ip_dst, hashval, port_range;
    struct iphdr *iph;
    uint32_t *data;
    uint16_t port;


    if (hashrnd_inited == 0) {
                vr_hashrnd = random();
        hashrnd_inited = 1;
    }

    if (pkt->vp_type == VP_TYPE_VXLAN) {

        if (pkt_head_len(pkt) < ETH_HLEN)
            goto error;

        data = (unsigned int *)(mbuf->buf_addr + pkt->vp_data);
        hashval = vr_hash(data, ETH_HLEN, vr_hashrnd);
        /* Include the VRF to calculate the hash */
        hashval = vr_hash_2words(hashval, vrf, vr_hashrnd);

    } else if (pkt->vp_type == VP_TYPE_L2) {
        /* Lets assume the ethernet header without VLAN headers as of now */

        pull_len = ETH_HLEN;
        if (pkt_head_len(pkt) < pull_len)
            goto error;

        data = (unsigned int *)pkt_data(pkt);
        /*
         * If L2 multicast and control data is zero, ethernet header is after
         * VXLAN and control word
         */
        if ((pkt->vp_flags & VP_FLAG_MULTICAST) && (!(*data))) {
            pull_len += VR_VXLAN_HDR_LEN + VR_L2_MCAST_CTRL_DATA_LEN;
            if (pkt_head_len(pkt) < pull_len)
                goto error;
            data = (unsigned int *)(((unsigned char *)data) +
                          VR_VXLAN_HDR_LEN + VR_L2_MCAST_CTRL_DATA_LEN);
        }

        hashval = vr_hash(data, ETH_HLEN, vr_hashrnd);
        /* Include the VRF to calculate the hash */
        hashval = vr_hash_2words(hashval, vrf, vr_hashrnd);
    } else {

        /*
         * Lets pull only if ip hdr is beyond this mbuf
         */
        pull_len = sizeof(struct iphdr);
        if ((pkt->vp_data + pull_len) > pkt->vp_tail) {
            /* We dont handle if tails are different */
            if (pkt->vp_tail != (mbuf->pkt.data - mbuf->buf_addr
                                + mbuf->pkt.data_len))
                goto error;

            pull_len += pkt->vp_data;
            pull_len -= rte_pktmbuf_headroom(mbuf);
            if (pull_len > mbuf->pkt.data_len) {
                goto error;
            }
        }

        iph = (struct iphdr *) (mbuf->buf_addr + pkt->vp_data);

        ip_src = iph->saddr;
        ip_dst = iph->daddr;

        hashval = rte_jhash_3words(ip_src, ip_dst, vrf, vr_hashrnd);
    }

    vr_dpdk_mbuf_reset(pkt);

    /*
     * Convert the hash value to a value in the port range that we want
     * for dynamic UDP ports
     */
    port_range = VR_MUDP_PORT_RANGE_END - VR_MUDP_PORT_RANGE_START;
    port = (uint16_t) (((uint64_t) hashval * port_range) >> 32);

    if (port > port_range) {
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

static void
dpdk_adjust_tcp_mss(struct tcphdr *tcph, struct rte_mbuf *m, unsigned short overlay_len)
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

            port_id = router->vr_eth_if->vif_os_idx;
            rte_eth_dev_get_mtu(port_id, &mtu);

            max_mss = mtu - (overlay_len + sizeof(struct vr_ip) +
                sizeof(struct tcphdr));

            if (pkt_mss > max_mss) {
                opt_ptr[opt_off+2] = (max_mss & 0xff00) >> 8;
                opt_ptr[opt_off+3] = max_mss & 0xff;

                /* Recalculate checksum */
                csum = (unsigned short)(~ntohs(tcph->check));
                csum = csum + (unsigned short)~pkt_mss;
                csum = (csum & 0xffff) + (csum >> 16);
                csum += max_mss;
                csum = (csum & 0xffff) + (csum >> 16);
                tcph->check = htons(~((unsigned short)csum));
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
    struct rte_mbuf *m;
    struct vr_ip *iph;
    struct tcphdr *tcph;
    int offset;

    m = vr_dpdk_pkt_to_mbuf(pkt);

    /* check if whole ip header is in the packet */
    offset = sizeof(struct vr_ip);
    if (pkt->vp_data + offset < pkt->vp_end)
        iph = (struct vr_ip *) ((uintptr_t)m->buf_addr + pkt->vp_data);
    else
        rte_panic("%s: ip header not in first buffer\n", __func__);

    if (iph->ip_proto != VR_IP_PROTO_TCP)
        goto out;

    /*
     * If this is a fragment and not the first one, it can be ignored
     */
    if (iph->ip_frag_off & htons(IP_OFFMASK))
        goto out;


    /*
     *  Now we know exact ip header length,
     *  check if whole tcp header is also in the packet
     */
    offset = (iph->ip_hl * 4) + sizeof(struct tcphdr);

    if (pkt->vp_data + offset < pkt->vp_end)
        tcph = (struct tcphdr *) ((char *) iph + (iph->ip_hl * 4));
    else
        rte_panic("%s: tcp header not in first buffer\n", __func__);

    if ((tcph->doff << 2) <= (sizeof(struct tcphdr))) {
        /*Nothing to do if there are no TCP options */
        goto out;
    }


    offset += (tcph->doff << 2) - sizeof(struct tcphdr);
    if (pkt->vp_data + offset > pkt->vp_end)
        rte_panic("%s: tcp header outside first buffer\n", __func__);


    dpdk_adjust_tcp_mss(tcph, m, overlay_len);

out:
    return 0;
}

static unsigned int
dpdk_pgso_size(struct vr_packet *pkt)
{
    /* TODO: not implemented */
    return 0;
}

struct host_os dpdk_host = {
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
    .hos_schedule_work              =    dpdk_schedule_work, /* not implemented */
    .hos_delay_op                   =    dpdk_delay_op, /* do nothing */
    .hos_defer                      =    dpdk_defer, /* for mirroring? */
    .hos_get_defer_data             =    dpdk_get_defer_data, /* for mirroring? */
    .hos_put_defer_data             =    dpdk_put_defer_data, /* for mirroring? */
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
    .hos_get_udp_src_port           =    dpdk_get_udp_src_port,
    .hos_pkt_from_vm_tcp_mss_adj    =    dpdk_pkt_from_vm_tcp_mss_adj,
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

    for (i = 0; i < VR_MAX_INTERFACES; i++) {
        vif = vr_dpdk.vhosts[i];
        if (vif != NULL) {
            vif_remove_xconnect(vif);
            if (vif->vif_bridge != NULL)
                vif_remove_xconnect(vif->vif_bridge);
        }
    }
}

/* Convert internal packet fields */
struct vr_packet *
vr_dpdk_packet_get(struct rte_mbuf *m, struct vr_interface *vif)
{
    struct vr_packet *pkt = vr_dpdk_mbuf_to_pkt(m);

    pkt->vp_cpu = vr_get_cpu();
    pkt->vp_data = rte_pktmbuf_headroom(m);
    pkt->vp_tail = rte_pktmbuf_headroom(m) + rte_pktmbuf_data_len(m);
    pkt->vp_len = rte_pktmbuf_data_len(m);
    pkt->vp_if = vif;
    pkt->vp_network_h = pkt->vp_inner_network_h = 0;
    pkt->vp_flags = 0;
    pkt->vp_nh = 0;
    pkt->vp_type = VP_TYPE_NULL;
    pkt->vp_ttl = 0;

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

/* Init vRouter */
int
vr_dpdk_host_init(void)
{
    int ret;
    int lcore_count = rte_lcore_count();

    if (vr_host_inited)
        return 0;

    ret = vrouter_init();
    if (ret)
        return ret;

    ret = vr_sandesh_init();
    if (ret)
        goto init_fail;

    dpdk_netlink_core_id = rte_get_master_lcore();
    if (lcore_count == 2) {
        dpdk_packet_core_id = dpdk_netlink_core_id;
    } else {
        dpdk_packet_core_id = rte_get_next_lcore(dpdk_netlink_core_id,
                1, 1);
    }

    vr_host_inited = true;

    return 0;

init_fail:
    vr_dpdk_host_exit();
    return ret;
}

