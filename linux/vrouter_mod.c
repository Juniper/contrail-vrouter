/*
 * vrouter_mod.c -- linux vrouter module
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/smp.h>
#include <linux/netdevice.h>
#include <linux/cpumask.h>
#include <linux/time.h>
#include <linux/highmem.h>
#include <linux/version.h>
#include <linux/if_vlan.h>
#include <linux/icmp.h>

#include "vr_packet.h"
#include "vr_sandesh.h"
#include "vrouter.h"
#include "vr_linux.h"
#include "vr_os.h"
#include "vr_compat.h"
#include "vr_hash.h"
#include "vr_fragment.h"
#include "vr_flow.h"
#include "vr_bridge.h"
#include "vr_packet.h"

unsigned int vr_num_cpus = 1;

extern int vr_flow_entries;
extern int vr_oflow_entries;

extern unsigned int vr_bridge_entries;
extern unsigned int vr_bridge_oentries;

int vrouter_dbg;

extern struct vr_packet *linux_get_packet(struct sk_buff *,
        struct vr_interface *);

extern bool linux_ip_proto_pull(struct iphdr *);

struct work_arg {
    struct work_struct wa_work;
    void (*fn)(void *);
    void *wa_arg;
};

struct rcu_cb_data {
    struct rcu_head rcd_rcu;
    vr_defer_cb rcd_user_cb;
    struct vrouter *rcd_router;
    unsigned char rcd_user_data[0];
};

extern int vrouter_init(void);
extern void vrouter_exit(bool);
extern int vr_genetlink_init(void);
extern void vr_genetlink_exit(void);
extern int vr_mem_init(void);
extern void vr_mem_exit(void);

extern void vhost_exit(void);

static void lh_reset_skb_fields(struct vr_packet *pkt);

static void *
lh_malloc(unsigned int size)
{
    return kmalloc(size, GFP_ATOMIC);
}

static void *
lh_zalloc(unsigned int size)
{
    return kzalloc(size, GFP_ATOMIC);
}

static void
lh_free(void *mem)
{
    if (mem)
        kfree(mem);

    return;
}

static void *
lh_page_alloc(unsigned int size)
{
    unsigned int order;

    if (size & (PAGE_SIZE - 1)) {
        size += PAGE_SIZE;
        size &= ~(PAGE_SIZE - 1);
    }

    order = get_order(size);

    return (void *)__get_free_pages(GFP_ATOMIC | __GFP_ZERO | __GFP_COMP, order);
}

static void
lh_page_free(void *address, unsigned int size)
{
    unsigned int order;

    if (size & (PAGE_SIZE - 1)) {
        size += PAGE_SIZE;
        size &= ~(PAGE_SIZE - 1);
    }

    order = get_order(size);

    free_pages((unsigned long)address, order);
    return;
}

uint64_t
lh_vtop(void *address)
{
    return (uint64_t)(virt_to_phys(address));
}

struct vr_packet *
lh_palloc(unsigned int size)
{
    struct sk_buff *skb;

    skb = alloc_skb(size, GFP_ATOMIC);
    if (!skb)
        return NULL;

    return linux_get_packet(skb, NULL);
}

static struct vr_packet *
lh_pexpand_head(struct vr_packet *pkt, unsigned int hspace)
{
    struct sk_buff *skb;

    skb = vp_os_packet(pkt);
    if (!skb)
        return NULL;

    if (pskb_expand_head(skb, hspace, 0, GFP_ATOMIC))
        return NULL;

    pkt->vp_head = skb->head;
    pkt->vp_data += hspace;
    pkt->vp_tail += hspace;
    pkt->vp_end = skb_end_pointer(skb) - skb->head;

    pkt->vp_network_h += hspace;
    pkt->vp_inner_network_h += hspace;

    return pkt;
}

static struct vr_packet *
lh_palloc_head(struct vr_packet *pkt, unsigned int size)
{
    struct sk_buff *skb, *skb_head;
    struct vr_packet *npkt;

    skb = vp_os_packet(pkt);
    if (!skb)
        return NULL;

    skb->data = pkt->vp_head + pkt->vp_data;
    skb_set_tail_pointer(skb, pkt->vp_len);
    skb->len = pkt->vp_len + skb->data_len;

    skb_head = alloc_skb(size, GFP_ATOMIC);
    if (!skb_head)
        return NULL;

    npkt = linux_get_packet(skb_head, pkt->vp_if);
    if (!npkt)
        return npkt;

    npkt->vp_ttl = pkt->vp_ttl;
    npkt->vp_flags = pkt->vp_flags;

    skb_frag_list_init(skb_head);
    skb_frag_add_head(skb_head, skb);
    skb_head->len += skb->len;
    skb_head->data_len = skb->len;
    skb_head->protocol = skb->protocol;

    /* Copy the gso fields too */
    skb_shinfo(skb_head)->gso_type = skb_shinfo(skb)->gso_type;
    skb_shinfo(skb_head)->gso_size = skb_shinfo(skb)->gso_size;
    skb_shinfo(skb_head)->gso_segs = skb_shinfo(skb)->gso_segs;
    skb_head->ip_summed = skb->ip_summed;
    skb_head->csum = skb->csum;

    npkt->vp_network_h += pkt->vp_network_h + npkt->vp_end;
    npkt->vp_inner_network_h += pkt->vp_inner_network_h + npkt->vp_end;

    return npkt;
}

static struct vr_packet *
lh_pclone(struct vr_packet *pkt)
{
    struct sk_buff *skb, *skb_c;
    struct vr_packet *pkt_clone;

    skb = vp_os_packet(pkt);
    skb_c = skb_clone(skb, GFP_ATOMIC);
    if (!skb_c)
        return NULL;

    pkt_clone = (struct vr_packet *)skb_c->cb;
    pkt_clone->vp_cpu = vr_get_cpu();

    return pkt_clone;
}


static void
lh_preset(struct vr_packet *pkt)
{
    struct sk_buff *skb;

    skb = vp_os_packet(pkt);
    pkt->vp_data = skb->data - skb->head;
    pkt->vp_tail = skb_tail_pointer(skb) - skb->head;
    pkt->vp_len = skb_headlen(skb);
    return;
}


static void
lh_pset_data(struct vr_packet *pkt, unsigned short offset)
{
    unsigned int skb_head_len;
    struct sk_buff *skb;

    skb = vp_os_packet(pkt);
    skb->data = pkt->vp_head + offset;
    skb_head_len = skb_tail_pointer(skb) - skb->data;
    skb->len = skb_head_len + skb->data_len;
     return;
}

static unsigned int
lh_pgso_size(struct vr_packet *pkt)
{
    struct sk_buff *skb = vp_os_packet(pkt);

    return skb_shinfo(skb)->gso_size;
}

static void
lh_pfree(struct vr_packet *pkt, unsigned short reason)
{
    struct vrouter *router = vrouter_get(0);
    struct sk_buff *skb;

    skb = vp_os_packet(pkt);
    if (!skb)
        return;

    if (router)
        ((uint64_t *)(router->vr_pdrop_stats[pkt->vp_cpu]))[reason]++;

    kfree_skb(skb);
    return;
}

void
lh_pfree_skb(struct sk_buff *skb, unsigned short reason)
{
    struct vrouter *router = vrouter_get(0);
    unsigned int cpu;

    cpu = vr_get_cpu();
    if ((cpu < vr_num_cpus) && (router))
        ((uint64_t *)(router->vr_pdrop_stats[cpu]))[reason]++;

    kfree_skb(skb);
    return;
}

static int
lh_pcopy(unsigned char *dst, struct vr_packet *p_src,
        unsigned int offset, unsigned int len)
{
    int ret;
    struct sk_buff *src;

    src = vp_os_packet(p_src);
    ret = skb_copy_bits(src, offset, dst, len);
    if (ret)
        return ret;

    return len;
}

static unsigned short
lh_pfrag_len(struct vr_packet *pkt)
{
    struct sk_buff *skb;

    skb = vp_os_packet(pkt);
    if (!skb)
        return 0;

    return skb->data_len;
}

static unsigned short
lh_phead_len(struct vr_packet *pkt)
{
    struct sk_buff *skb;

    skb = vp_os_packet(pkt);
    if (!skb)
        return 0;

    return skb_headlen(skb);
}

static void
lh_get_time(unsigned int *sec, unsigned int *nsec)
{
    struct timespec t;

    getnstimeofday(&t);
    *sec = t.tv_sec;
    *nsec = t.tv_nsec;

    return;
}

static unsigned int
lh_get_cpu(void)
{
    unsigned int cpu = get_cpu();
    put_cpu();

    return cpu;
}

static void
lh_get_mono_time(unsigned int *sec, unsigned int *nsec)
{
    struct timespec t;
    uint64_t jiffies = get_jiffies_64();

    jiffies_to_timespec(jiffies, &t);
    *sec = t.tv_sec;
    *nsec = t.tv_nsec;

    return;
}

static void
lh_work(struct work_struct *work)
{
    struct work_arg *wa = container_of(work, struct work_arg, wa_work);

    rcu_read_lock();
    wa->fn(wa->wa_arg);
    rcu_read_unlock();
    kfree(wa);

    return;
}

static void
lh_schedule_work(unsigned int cpu, void (*fn)(void *), void *arg)
{
    struct work_arg *wa = kzalloc(sizeof(*wa), GFP_KERNEL);

    if (!wa)
        return;

    wa->fn = fn;
    wa->wa_arg = arg;
    INIT_WORK(&wa->wa_work, lh_work);
    schedule_work_on(cpu, &wa->wa_work);

    return;
}

static void
lh_delay_op(void)
{
    synchronize_net();
    return;
}

static void *
lh_inner_network_header(struct vr_packet *pkt)
{
    struct sk_buff *skb;
    struct sk_buff *frag;
    struct vr_packet *frag_pkt;
    unsigned short off = pkt->vp_inner_network_h - pkt->vp_end;

    skb = vp_os_packet(pkt);

    while (skb_shinfo(skb)->frag_list) {
        frag = skb_shinfo(skb)->frag_list;
        frag_pkt = (struct vr_packet *)frag->cb;
        if (off < frag_pkt->vp_end)
            return frag_pkt->vp_head + off;
        off -= frag_pkt->vp_end;
        skb = frag;
    }

    return NULL;
}

/*
 * lh_pheader_pointer - wrapper for skb_header_pointer
 */
static void *
lh_pheader_pointer(struct vr_packet *pkt, unsigned short hdr_len, void *buf)
{
    int offset;
    struct sk_buff *skb = vp_os_packet(pkt);

    /*
     * vp_data is the offset from the skb head. skb_header_pointer expects
     * the offset from skb->data, so calculate this offset.
     */
    offset = pkt->vp_data - (skb->data - skb->head);
    return skb_header_pointer(skb, offset, hdr_len, buf);
}

static void
rcu_cb(struct rcu_head *rh)
{
    struct rcu_cb_data *cb_data = (struct rcu_cb_data *)rh;

    /* Call the user call back */
    cb_data->rcd_user_cb(cb_data->rcd_router, cb_data->rcd_user_data);
    lh_free(cb_data);

    return;
}

static void
lh_defer(struct vrouter *router, vr_defer_cb user_cb, void *data)
{
    struct rcu_cb_data *cb_data;

    cb_data = container_of(data, struct rcu_cb_data, rcd_user_data);
    cb_data->rcd_user_cb = user_cb;
    cb_data->rcd_router = router;
    call_rcu(&cb_data->rcd_rcu, rcu_cb);

    return;
}

static void *
lh_get_defer_data(unsigned int len)
{
    struct rcu_cb_data *cb_data;

    if (!len)
        return NULL;

    cb_data = lh_malloc(sizeof(*cb_data) + len);
    if (!cb_data) {
        return NULL;
    }

    return cb_data->rcd_user_data;
}

static void
lh_put_defer_data(void *data)
{
    struct rcu_cb_data *cb_data;

    if (!data)
        return;

    cb_data = container_of(data, struct rcu_cb_data, rcd_user_data);
    lh_free(cb_data);

    return;
}

static int
lh_pcow(struct vr_packet *pkt, unsigned short head_room)
{
    unsigned int old_off, new_off;
    int data_off = 0;

    struct sk_buff *skb = vp_os_packet(pkt);

    data_off = pkt->vp_data - (skb->data - skb->head);

#ifdef NET_SKBUFF_DATA_USES_OFFSET
    old_off = skb->network_header;
#else
    old_off = skb->network_header - skb->head;
#endif
    if (skb_cow(skb, head_room)) 
        return -ENOMEM;
    /* Now manipulate the offsets as data pointers are modified */
    pkt->vp_head = skb->head;
    pkt->vp_tail = skb_tail_pointer(skb) - skb->head;

    /* The data_off, can be negative here */
    pkt->vp_data = skb->data - skb->head + data_off;
    pkt->vp_end = skb_end_pointer(skb) - skb->head;
    /*
     * pkt->vp_len is untouched, as it is going to be same
     * before and after cow
     */
#ifdef NET_SKBUFF_DATA_USES_OFFSET
    new_off = skb->network_header;
#else
    new_off = skb->network_header - skb->head;
#endif
    pkt->vp_network_h += new_off - old_off;
    pkt->vp_inner_network_h += new_off - old_off;

    return 0;
}

/*
 * lh_get_udp_src_port - return a source port for the outer UDP header.
 * The source port is based on a hash of the inner IP source/dest addresses,
 * vrf (and inner TCP/UDP ports in the future). The label from fmd
 * will be used in the future to detect whether it is a L2/L3 packet.
 * Returns 0 on error, valid source port otherwise.
 */
static __u16
lh_get_udp_src_port(struct vr_packet *pkt, struct vr_forwarding_md *fmd,
                    unsigned short vrf)
{
    struct sk_buff *skb = vp_os_packet(pkt);
    int pull_len;
    __u32 ip_src, ip_dst, hashval, port_range;
    struct vr_ip *iph;
    __u16 port;
    __u16 sport = 0, dport = 0;
    struct vr_fragment *frag;
    struct vrouter *router = vrouter_get(0);
    __u32 hash_key[5];
    __u16 *l4_hdr;
    struct vr_flow_entry *fentry;

    if (hashrnd_inited == 0) {
        get_random_bytes(&vr_hashrnd, sizeof(vr_hashrnd));
        hashrnd_inited = 1;
    }

    if (vr_pkt_is_l2(pkt)) {
        if (pkt_head_len(pkt) < ETH_HLEN)
            goto error;

        hashval = vr_hash(pkt_data(pkt), ETH_HLEN, vr_hashrnd);
        /* Include the VRF to calculate the hash */
        hashval = vr_hash_2words(hashval, vrf, vr_hashrnd);
    } else  {
        /* Ideally the below code is only for VP_TYPE_IP and not
         * for IP6. But having explicit check for IP only break IP6
         */

        /*
         * pull_len can be negative in the following calculation. This behavior
         * will be true in case of mirroring. In mirroring, we do preset first
         * which makes vp_data = skb->data, and then we push mirroring headers,
         * which makes pull_len < 0 and thats why pull_len is an integer.
         */
        pull_len = sizeof(struct iphdr);
        pull_len += pkt_get_network_header_off(pkt);
        pull_len -= skb_headroom(skb);

        /* Lets pull only if ip hdr is beyond this skb */
        if ((pkt_get_network_header_off(pkt) + sizeof(struct iphdr)) >
                pkt->vp_tail) {
            /* We dont handle if tails are different */
#ifdef NET_SKBUFF_DATA_USES_OFFSET
            if (pkt->vp_tail != skb->tail)
#else
            if (pkt->vp_tail != (skb->tail - skb->head))
                goto error;
#endif
            /*
             * pull_len has to be +ve here and hence additional check is not
             * needed
             */
            if (!pskb_may_pull(skb, (unsigned int)pull_len))
                goto error;
        }

        iph = (struct vr_ip *)(skb->head + pkt_get_network_header_off(pkt));
        if (vr_ip_transport_header_valid(iph)) {
            if ((iph->ip_proto == VR_IP_PROTO_TCP) ||
                        (iph->ip_proto == VR_IP_PROTO_UDP)) {
                pull_len += ((iph->ip_hl * 4) - sizeof(struct vr_ip) + 4);
                if ((pull_len > 0) &&
                            !pskb_may_pull(skb,(unsigned int)pull_len)) {
                    goto error;
                }
                iph = (struct vr_ip *)(skb->head +
                        pkt_get_network_header_off(pkt));
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
            fentry = vr_get_flow_entry(router, fmd->fmd_flow_index);
            if (fentry) {
                lh_reset_skb_fields(pkt);
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

        hashval = jhash(hash_key, 20, vr_hashrnd);
    }


    lh_reset_skb_fields(pkt);

    /*
     * Convert the hash value to a value in the port range that we want
     * for dynamic UDP ports
     */
    port_range = VR_MUDP_PORT_RANGE_END - VR_MUDP_PORT_RANGE_START;
    port = (__u16) (((u64) hashval * port_range) >> 32);

    if (port > port_range) {
        /* 
         * Shouldn't happen...
         */
        port = 0;
    }

    return (port + VR_MUDP_PORT_RANGE_START);

error:
    lh_reset_skb_fields(pkt);
    return 0;
}

/*
 * lh_adjust_tcp_mss - adjust the TCP MSS in the given packet based on
 * vrouter physical interface MTU. Returns 0 on success, non-zero
 * otherwise.
 */
static void 
lh_adjust_tcp_mss(struct tcphdr *tcph, struct sk_buff *skb, unsigned short overlay_len, unsigned short hlen)
{
    int opt_off = sizeof(struct tcphdr);
    u8 *opt_ptr = (u8 *) tcph;
    u16 pkt_mss, max_mss;
    struct net_device *dev;
    struct vrouter *router = vrouter_get(0);

    if ((tcph == NULL) || (!tcph->syn) || (router == NULL)) {
        return;
    }

    if (router->vr_eth_if == NULL) {
        return;
    }

    while (opt_off < (tcph->doff*4)) {
        switch (opt_ptr[opt_off]) {
            case TCPOPT_EOL:
                return;

            case TCPOPT_NOP:
                opt_off++;
                continue;

            case TCPOPT_MSS:
                if ((opt_off + TCPOLEN_MSS) > (tcph->doff*4)) {
                    return;
                }

                if (opt_ptr[opt_off+1] != TCPOLEN_MSS) {
                    return;
                }

                pkt_mss = (opt_ptr[opt_off+2] << 8) | opt_ptr[opt_off+3];
                dev = (struct net_device *) router->vr_eth_if->vif_os;
                if (dev == NULL) {
                    return;
                }

                max_mss = dev->mtu -
                             (overlay_len + hlen + sizeof(struct tcphdr));

                if (pkt_mss > max_mss) {
                    opt_ptr[opt_off+2] = (max_mss & 0xff00) >> 8;
                    opt_ptr[opt_off+3] = max_mss & 0xff;

                    inet_proto_csum_replace2(&tcph->check, skb,
                                             htons(pkt_mss),
                                             htons(max_mss), 0);
                }

                return;

            default:

                if ((opt_off + 1) == (tcph->doff*4)) {
                    return;
                }

                if (opt_ptr[opt_off+1]) {
                    opt_off += opt_ptr[opt_off+1];
                } else {
                    opt_off++;
                }

                continue;
        } /* switch */
    } /* while */

    return;
}

/*
 * lh_pkt_from_vm_tcp_mss_adj - perform TCP MSS adjust, if required, for packets
 * that are sent by a VM. Returns 0 on success, non-zero otherwise.
 */
static int
lh_pkt_from_vm_tcp_mss_adj(struct vr_packet *pkt, unsigned short overlay_len)
{
    struct sk_buff *skb = vp_os_packet(pkt);
    int hlen, pull_len, proto, opt_len = 0;
    struct vr_ip *iph;
    struct vr_ip6 *ip6h;
    struct tcphdr *tcph;

    /*
     * Pull enough of the header into the linear part of the skb to be
     * able to inspect/modify the TCP header MSS value.
     */
    iph = (struct vr_ip *) (skb->head + pkt->vp_data);

    pull_len = pkt->vp_data - (skb_headroom(skb));

    /* Pull in ipv4 header-length */
    pull_len += sizeof(struct vr_ip);

    if (!pskb_may_pull(skb, pull_len)) {
        return VP_DROP_PULL; 
    }

    iph = (struct vr_ip *) (skb->head + pkt->vp_data);

    if (vr_ip_is_ip6(iph)) {

        pull_len += (sizeof(struct vr_ip6) - sizeof(struct vr_ip));
        if (!pskb_may_pull(skb, pull_len)) {
            return VP_DROP_PULL;
        }

        ip6h = (struct vr_ip6 *) (skb->head + pkt->vp_data);
        proto = ip6h->ip6_nxt;
        hlen = sizeof(struct vr_ip6);
    } else {
        /*
         * If this is a fragment and not the first one, it can be ignored
         */
        if (iph->ip_frag_off & htons(IP_OFFSET)) {
            goto out;
        }

        proto = iph->ip_proto;
        hlen = iph->ip_hl * 4;
        opt_len = hlen - sizeof(struct vr_ip);
    }


    if (proto != VR_IP_PROTO_TCP) {
        goto out;
    }

    pull_len += sizeof(struct tcphdr) + opt_len;

    if (!pskb_may_pull(skb, pull_len)) {
        return VP_DROP_PULL;
    }

    tcph = (struct tcphdr *) ((char *) iph +  hlen);

    if ((tcph->doff << 2) <= (sizeof(struct tcphdr))) {
        /*
         * Nothing to do if there are no TCP options
         */
        goto out;
    }

    pull_len += ((tcph->doff << 2) - (sizeof(struct tcphdr)));

    if (!pskb_may_pull(skb, pull_len)) {
        return VP_DROP_PULL;
    }

    iph = (struct vr_ip *) (skb->head + pkt->vp_data);
    tcph = (struct tcphdr *) ((char *) iph +  hlen);

    lh_adjust_tcp_mss(tcph, skb, overlay_len, hlen);

out:
    lh_reset_skb_fields(pkt);

    return 0;
}
    
/*
 * lh_reset_skb_fields - if the skb changes, possibley due to pskb_may_pull,
 * reset fields of the pkt structure that point at the skb fields.
 */
static void
lh_reset_skb_fields(struct vr_packet *pkt)
{
    struct sk_buff *skb = vp_os_packet(pkt);

    pkt->vp_head = skb->head;
    pkt->vp_tail = skb_tail_pointer(skb) - skb->head;
    pkt->vp_end = skb_end_pointer(skb) - skb->head;
    pkt->vp_len = pkt->vp_tail - pkt->vp_data;

   return;
}

/*
 * lh_csum_verify_fast - faster version of skb_checksum which avoids a call
 * to kmap_atomic/kunmap_atomic as we already have a pointer obtained
 * from an earlier call to kmap_atomic. This function can only be used if
 * the skb has a TCP segment contained entirely in a single frag. Returns 0
 * if checksum is ok, non-zero otherwise.
 */
static int
lh_csum_verify_fast(struct vr_ip *iph, struct tcphdr *tcph,
                    unsigned int tcp_size)
{
    __wsum csum;

    csum = csum_tcpudp_nofold(iph->ip_saddr, iph->ip_daddr,
                              tcp_size, IPPROTO_TCP, 0);
    if (csum_fold(csum_partial(tcph, tcp_size, csum))) {
        return -1;
    }

    return 0;
}

/*
 * lh_csum_verify - verifies checksum of skb containing a TCP segment. Returns
 * 0 if checksum is ok, non-zero otherwise.
 */
static int
lh_csum_verify(struct sk_buff *skb, struct vr_ip *iph)
{
    skb->csum = csum_tcpudp_nofold(iph->ip_saddr, iph->ip_daddr,
                                   ntohs(iph->ip_len) - (iph->ip_hl * 4), 
                                   IPPROTO_TCP, 0);
    if (__skb_checksum_complete(skb)) {
        return -1;
    }

    return 0;
}

/*
 * lh_handle_checksum_complete_skb - if the skb has CHECKSUM_COMPLETE set,
 * set it to CHECKSUM_NONE. 
 */
static void
lh_handle_checksum_complete_skb(struct sk_buff *skb)
{
    if (skb->ip_summed == CHECKSUM_COMPLETE) {
        skb->csum = 0;
        skb->ip_summed = CHECKSUM_NONE;
    }
}

/*
 * lh_csum_verify_udp - verifies checksum of skb containing a UDP datagram.
 * Returns 0 if checksum is ok, non-zero otherwise.
 */
static int
lh_csum_verify_udp(struct sk_buff *skb, struct vr_ip *iph)
{
    if (skb->ip_summed == CHECKSUM_COMPLETE) {
        if (!csum_tcpudp_magic(iph->ip_saddr, iph->ip_daddr,
                               skb->len, IPPROTO_UDP, skb->csum)) {
            skb->ip_summed = CHECKSUM_UNNECESSARY;
            return 0;
        }
    }

    skb->csum = csum_tcpudp_nofold(iph->ip_saddr, iph->ip_daddr,
                                   skb->len, IPPROTO_UDP, 0);
    if (__skb_checksum_complete(skb)) {
        return -1;
    }

    return 0;
}

/*
 * vr_kmap_atomic - calls kmap_atomic with right arguments depending on
 * kernel version. For now, does nothing on 2.6.32 as we won't call this
 * function on 2.6.32.
 */
static void *
vr_kmap_atomic(struct page *page)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
#if defined(RHEL_MAJOR) && defined(RHEL_MINOR) && \
           (RHEL_MAJOR == 6) && (RHEL_MINOR == 4)
    return kmap_atomic(page, KM_SKB_DATA_SOFTIRQ);
#else 
    return NULL;
#endif
#else
    return kmap_atomic(page);
#endif
}

/*
 * vr_kunmap_atomic - calls kunmap_atomic with right arguments depending on
 * kernel version. For now, does nothing on 2.6.32 as we won't call this
 * function on 2.6.32.
 */
static void
vr_kunmap_atomic(void *va)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
#if defined(RHEL_MAJOR) && defined(RHEL_MINOR) && \
           (RHEL_MAJOR == 6) && (RHEL_MINOR == 4)
    kunmap_atomic(va, KM_SKB_DATA_SOFTIRQ); 
#else 
    return;
#endif
#else
    kunmap_atomic(va);
#endif
}

/*
 * lh_pull_inner_headers_fast_udp - implements the functionality of
 * lh_pull_inner_headers_fast for UDP packets.
 */
static int
lh_pull_inner_headers_fast_udp(struct vr_packet *pkt, int
                               (*tunnel_type_cb)(unsigned int, unsigned
                                   int, unsigned short *), int *ret, 
                               int *encap_type)
{
    struct sk_buff *skb = vp_os_packet(pkt);
    unsigned short pkt_headlen, eth_proto;
    unsigned char *va = NULL;
    skb_frag_t *frag;
    unsigned int frag_size, pull_len, hdr_len, skb_pull_len, tcp_size;
    unsigned int  tcph_pull_len = 0, hlen = 0;
    struct vr_ip *iph = NULL, *icmp_pl_iph = NULL;
    struct vr_udp *udph;
    struct tcphdr *tcph = NULL;
    struct vr_icmp *icmph = NULL;
    bool thdr_valid = false;
    unsigned int label, control_data;
    int pkt_type = 0;
    struct vr_eth *eth = NULL;
    struct vr_ip *outer_iph = NULL;
    unsigned short th_csum = 0;

    pkt_headlen = pkt_head_len(pkt);
    hdr_len = sizeof(struct udphdr);

    if (pkt_headlen) {
        if (pkt_headlen != hdr_len) {
            goto slow_path;
        }
    }

    /*
     * At this point, either the entire UDP header is contained in the linear
     * part of the skb (if pkt_headlen is non-zero) OR the entire UDP header
     * is contained in the non-linear part of the skb (if pkt_headlen is 0).
     * If the skb does not have a paged frag, take the slow path. This might
     * happen in the rare case of a skb with a frag-list.
     */
    if ((!skb_shinfo(skb)->nr_frags) ||
                 skb_shinfo(skb)->frag_list) {
        goto slow_path;
    }

    frag = &skb_shinfo(skb)->frags[0];
    frag_size = skb_frag_size(frag);
    va = vr_kmap_atomic(skb_frag_page(frag));
    va += frag->page_offset;

    pull_len = 0;
    if (pkt_headlen == 0) {
        pull_len = hdr_len;
        udph = (struct vr_udp *) va;
    } else {
        udph = (struct vr_udp *) pkt_data(pkt);
    }

    if (ntohs(udph->udp_dport) == VR_MPLS_OVER_UDP_DST_PORT) {

        *encap_type = PKT_ENCAP_MPLS;
        /* Take into consideration, the MPLS header and 4 bytes of
         * control information that might exist for L2 packet */
        if (frag_size < (pull_len + VR_MPLS_HDR_LEN +
                                VR_L2_MCAST_CTRL_DATA_LEN))
            goto slow_path;

        label = ntohl(*(uint32_t *)(va + pull_len));
        control_data = *(uint32_t *)(va + pull_len + VR_MPLS_HDR_LEN);

        /* Identify whether the packet is L2 or not using the label and
         * control data */
        pkt_type = tunnel_type_cb(label, control_data, NULL);
        if (pkt_type <= 0)
            goto unhandled;

        if (pkt_type == PKT_MPLS_TUNNEL_L3) {
            /* L3 packet */
            iph = (struct vr_ip *) (va + pull_len + VR_MPLS_HDR_LEN);
            if (!vr_ip_is_ip6(iph)) {
                pull_len += VR_MPLS_HDR_LEN + sizeof(struct vr_ip);
            } else {
                pull_len += VR_MPLS_HDR_LEN + sizeof(struct vr_ip6);
                iph = NULL;
            }
        } else if (pkt_type == PKT_MPLS_TUNNEL_L2_MCAST) {
            /* L2 Multicast packet with control information and 
             * Vxlan header. Vxlan header contains IP + UDP + Vxlan */
            eth = (struct vr_eth *)(va + pull_len + VR_MPLS_HDR_LEN +
                    VR_L2_MCAST_CTRL_DATA_LEN + VR_VXLAN_HDR_LEN);
            pull_len += VR_MPLS_HDR_LEN + VR_L2_MCAST_CTRL_DATA_LEN +
                            VR_VXLAN_HDR_LEN + sizeof(struct vr_eth);
        } else if ((pkt_type == PKT_MPLS_TUNNEL_L2_UCAST) ||
                    (pkt_type == PKT_MPLS_TUNNEL_L2_MCAST_EVPN)) {
            /* L2 packet with no control information */
            eth = (struct vr_eth *)(va + pull_len + VR_MPLS_HDR_LEN);
            pull_len += VR_MPLS_HDR_LEN + sizeof(struct vr_eth);
        } else {
            goto unhandled;
        }

        if (frag_size < pull_len) 
            goto slow_path;

    } else if (ntohs(udph->udp_dport) == VR_VXLAN_UDP_DST_PORT) {
        *encap_type = PKT_ENCAP_VXLAN;
        /* Take into consideration, the VXLAN header ethernet header */
        pull_len += sizeof(struct vr_vxlan) + ETH_HLEN;
        if (frag_size < pull_len)
            goto slow_path;

        eth = (struct vr_eth *)(va + sizeof(struct vr_vxlan));
    } else {
        goto unhandled;
    }

    if (eth) {

        eth_proto = eth->eth_proto;
        while (ntohs(eth_proto) == VR_ETH_PROTO_VLAN) {
            eth_proto = ((struct vr_vlan_hdr *) (va + pull_len))->vlan_proto;
            pull_len += sizeof(struct vr_vlan_hdr);
            if (frag_size < pull_len)
                goto slow_path;
        }

        if (ntohs(eth_proto) == VR_ETH_PROTO_IP) {
            iph = (struct vr_ip *)(va + pull_len);
            pull_len += sizeof(struct iphdr);
            if (frag_size < pull_len)
                goto slow_path;
        }

        if (ntohs(eth_proto) == VR_ETH_PROTO_ARP) {
            pull_len += sizeof(struct vr_arp);
            if (frag_size < pull_len)
                goto slow_path;
        }
    }


    if (iph) {
        /*
         * Account for IP options
         */
        thdr_valid = vr_ip_transport_header_valid(iph);
        if (thdr_valid) {
            hlen = iph->ip_hl * 4;
            pull_len += (hlen - sizeof(struct vr_ip));
            tcph_pull_len = pull_len;
            if (iph->ip_proto == VR_IP_PROTO_TCP) {
                pull_len += sizeof(struct tcphdr);
            } else if (iph->ip_proto == VR_IP_PROTO_UDP) {
                pull_len += sizeof(struct udphdr);
            } else if (iph->ip_proto == VR_IP_PROTO_ICMP) {
                pull_len += sizeof(struct icmphdr);
            }

            if (frag_size < pull_len) {
                goto slow_path;
            }

            if (iph->ip_proto == VR_IP_PROTO_TCP) {
                /*
                 * Account for TCP options
                 */
                tcph = (struct tcphdr *) ((char *) iph +  hlen);

                /*
                 * If SYN, send it to the slow path for possible TCP MSS
                 * adjust.
                 */
                if (tcph->syn && vr_to_vm_mss_adj) {
                    goto slow_path;
                }

                if ((tcph->doff << 2) > (sizeof(struct tcphdr))) {
                    pull_len += ((tcph->doff << 2) - (sizeof(struct tcphdr)));

                    if (frag_size < pull_len) {
                        goto slow_path;
                    }
                }
                th_csum = tcph->check;
            } else if (iph->ip_proto == VR_IP_PROTO_ICMP) {
                icmph = (struct vr_icmp *)((unsigned char *)iph + hlen);
                th_csum = icmph->icmp_csum;
                if (vr_icmp_error(icmph)) {
                    pull_len += sizeof(struct vr_ip);
                    if (frag_size < pull_len)
                        goto slow_path;
                    icmp_pl_iph = (struct vr_ip *)(icmph + 1);
                    pull_len += (icmp_pl_iph->ip_hl * 4) - sizeof(struct vr_ip);
                    if (frag_size < pull_len)
                        goto slow_path;
                    if (linux_ip_proto_pull((struct iphdr *)icmp_pl_iph)) {
                        if (icmp_pl_iph->ip_proto == VR_IP_PROTO_TCP)
                            pull_len += sizeof(struct vr_tcp);
                        else if (icmp_pl_iph->ip_proto == VR_IP_PROTO_UDP)
                            pull_len += sizeof(struct vr_udp);
                        else
                            pull_len += sizeof(struct vr_icmp);

                        if (frag_size < pull_len)
                            goto slow_path;

                        if (icmp_pl_iph->ip_proto == VR_IP_PROTO_TCP) {
                            th_csum = ((struct vr_tcp *)
                                    ((unsigned char *)icmp_pl_iph +
                                     icmp_pl_iph->ip_hl * 4))->tcp_csum;
                        } else if (icmp_pl_iph->ip_proto == VR_IP_PROTO_UDP) {
                            th_csum = ((struct vr_udp *)
                                    ((unsigned char *)icmp_pl_iph +
                                     icmp_pl_iph->ip_hl * 4))->udp_csum;
                        } else if (icmp_pl_iph->ip_proto == VR_IP_PROTO_ICMP) {
                            th_csum = ((struct vr_icmp *)
                                    ((unsigned char *)icmp_pl_iph +
                                     icmp_pl_iph->ip_hl * 4))->icmp_csum;
                        }
                    }
                }
            } else if (iph->ip_proto == VR_IP_PROTO_UDP) {
                th_csum = ((struct udphdr *)
                        ((unsigned char *)iph + hlen))->check;
            }
        }
    }

    if ((skb->end - skb->tail) < pull_len) {
        goto slow_path;
    }

    memcpy(skb_tail_pointer(skb), va, pull_len);
    skb_frag_size_sub(frag, pull_len);
    frag->page_offset += pull_len;
    skb->data_len -= pull_len;
    skb->tail += pull_len;

    lh_reset_skb_fields(pkt);

    /*
     * Verify the checksum if the NIC didn't already do it. If the outer
     * header is UDP and has a non-zero checksum, we don't need to verify  
     * the inner packet's checksum. Otherwise, verify the inner packet's
     * checksum if the packet is not a fragment.
     */
    if (udph->udp_csum != 0) {
        if (!skb_csum_unnecessary(skb)) {
            skb_pull_len = pkt_data(pkt) - skb->data;

            skb_pull(skb, skb_pull_len);
            outer_iph = (struct vr_ip *)pkt_network_header(pkt);
            if (lh_csum_verify_udp(skb, outer_iph)) {
                if (th_csum == VR_DIAG_CSUM) {
                    vr_pkt_set_diag(pkt);
                } else {
                    goto cksum_err;
                }
            }
            /*
             * Restore the skb back to its original state. This is required as
             * packets that get trapped to the agent assume that the skb is
             * unchanged from the time it is received by vrouter.
             */
            skb_push(skb, skb_pull_len);
        }
    } else {
        /*
         * Verify inner packet checksum if it is TCP as we only do GRO for TCP
         * (and GRO requires that checksum has been verified). For all other
         * protocols, we will let the guest verify the checksum.
         */
        if (iph && (!vr_ip_fragment(iph))) {
            if (iph->ip_proto == VR_IP_PROTO_TCP) {
                lh_handle_checksum_complete_skb(skb);

                if (skb_shinfo(skb)->nr_frags == 1) {
                    tcp_size = ntohs(iph->ip_len) - hlen;
                    if (lh_csum_verify_fast(iph, tcph, tcp_size)) {
                        if (th_csum == VR_DIAG_CSUM) {
                            vr_pkt_set_diag(pkt);
                        } else {
                            goto cksum_err;
                        }
                    }
                } else {
                    /*
                     * Pull to the start of the TCP header
                     */
                    skb_pull_len = (pkt_data(pkt) - skb->data) +
                                   pkt_headlen + tcph_pull_len;

                    skb_pull(skb, skb_pull_len);
                    if (lh_csum_verify(skb, iph)) {
                        if (th_csum == VR_DIAG_CSUM) {
                            vr_pkt_set_diag(pkt);
                        } else {
                            goto cksum_err;
                        }
                    }

                    /*
                     * Restore the skb back to its original state. This is
                     * required as packets that get trapped to the agent
                     * assumes that the packet is unchanged from the time
                     * it is received by vrouter.
                     */
                    skb_push(skb, skb_pull_len);
                }

                skb->ip_summed = CHECKSUM_UNNECESSARY;
            } else {
                /*
                 * If outer UDP header had checksum of 0 and the inner packet
                 * is not TCP, set ip_summed to indicate that checksum
                 * verification is required.
                 */
                if (th_csum == VR_DIAG_CSUM) {
                    vr_pkt_set_diag(pkt);
                }

                skb->ip_summed &= (~CHECKSUM_UNNECESSARY);
            }
        }
    }

    if ((*encap_type == PKT_ENCAP_VXLAN) ||
            (pkt_type != PKT_MPLS_TUNNEL_L3)) {
        if (skb->ip_summed == CHECKSUM_PARTIAL)
            skb->ip_summed = CHECKSUM_UNNECESSARY;
    }

    pkt_pull(pkt, hdr_len);

    if (va) {
        vr_kunmap_atomic(va);
    }

    *ret = PKT_RET_FAST_PATH;
    return 1;

unhandled:
    if (va) {
        vr_kunmap_atomic(va);
    }

    return 0;

cksum_err:
    if (va) {
        vr_kunmap_atomic(va);
    }

    *ret = PKT_RET_ERROR;
    return 1;

slow_path:
    if (va) {
        vr_kunmap_atomic(va);
    }

    *ret = PKT_RET_SLOW_PATH;
    return 1;
}

/*
 * lh_pull_inner_headers_fast_gre - implements the functionality of
 * lh_pull_inner_headers_fast for GRE packets.
 */
static int
lh_pull_inner_headers_fast_gre(struct vr_packet *pkt, int
        (*tunnel_type_cb)(unsigned int, unsigned int, unsigned short *),
        int *ret, int *encap_type)
{
    struct sk_buff *skb = vp_os_packet(pkt);
    unsigned short pkt_headlen, *gre_hdr = NULL, gre_proto,
                   hdr_len = VR_GRE_BASIC_HDR_LEN, eth_proto;
    unsigned char *va = NULL;
    skb_frag_t *frag;
    unsigned int frag_size, pull_len, hlen = 0, tcp_size, skb_pull_len,
                 label, control_data, tcph_pull_len = 0, l2_len = 0;
    unsigned short th_csum = 0;
    struct vr_ip *iph  = NULL, *icmp_pl_iph = NULL;
    struct tcphdr *tcph = NULL;
    struct vr_icmp *icmph = NULL;
    bool thdr_valid = false;
    struct vr_eth *eth = NULL;
    int pkt_type;

    *encap_type = PKT_ENCAP_MPLS;
    pkt_headlen = pkt_head_len(pkt);
    if (pkt_headlen) {
        if (pkt_headlen > hdr_len) {
            gre_hdr = (unsigned short *) pkt_data(pkt);
            if (gre_hdr && (*gre_hdr & VR_GRE_FLAG_CSUM)) {
                hdr_len += (VR_GRE_CKSUM_HDR_LEN - VR_GRE_BASIC_HDR_LEN);
            }

            if (gre_hdr && (*gre_hdr & VR_GRE_FLAG_KEY)) {
                hdr_len += (VR_GRE_KEY_HDR_LEN - VR_GRE_BASIC_HDR_LEN);
            }

            if (pkt_headlen > hdr_len) {
                /*
                 * If the packet has more than the GRE header in the linear part
                 * of the skb, we assume that it has the whole packet in the
                 * linear part, so the calls to pskb_may_pull() in the slow path
                 * shouldn't be expensive.
                 */
                goto slow_path;
            }
        }

        if (pkt_headlen < hdr_len) {
            /*
             * If the linear part of the skb has only a part of the header,
             * take the slow path and let pskb_may_pull() handle corner cases.
             */
            goto slow_path;
        }

        /*
         * pkt_headlen has to be equal to hdr_len. Check if the GRE header
         * is split between the linear part and the non-linear part of the
         * skb. If yes, take the slow path.
         */
        if (gre_hdr == NULL) {
            gre_hdr = (unsigned short *) pkt_data(pkt);
            if (gre_hdr && (*gre_hdr & (VR_GRE_FLAG_CSUM | VR_GRE_FLAG_KEY))) {
                goto slow_path;
            }
        }
    }

    /*
     * At this point, either the entire GRE header is contained in the linear
     * part of the skb (if pkt_headlen is non-zero) OR the entire GRE header
     * is contained in the non-linear part of the skb (if pkt_headlen is 0).
     * If the skb does not have a paged frag, take the slow path. This might
     * happen in the rare case of a skb with a frag-list.
     */
    if ((!skb_shinfo(skb)->nr_frags) ||
                 skb_shinfo(skb)->frag_list) {
        goto slow_path;
    }

    frag = &skb_shinfo(skb)->frags[0];
    frag_size = skb_frag_size(frag);
    va = vr_kmap_atomic(skb_frag_page(frag));
    va += frag->page_offset;

    pull_len = 0;
    if (pkt_headlen == 0) {
        if (frag_size < VR_GRE_BASIC_HDR_LEN) {
            goto slow_path;
        }

        gre_hdr = (unsigned short *) va;
        if (gre_hdr && (*gre_hdr & VR_GRE_FLAG_CSUM)) {
            if (frag_size < VR_GRE_CKSUM_HDR_LEN) {
                goto slow_path;
            }

            hdr_len += (VR_GRE_CKSUM_HDR_LEN - VR_GRE_BASIC_HDR_LEN);
        }

        if (gre_hdr && (*gre_hdr & VR_GRE_FLAG_KEY)) {
            hdr_len += (VR_GRE_KEY_HDR_LEN - VR_GRE_BASIC_HDR_LEN);
            if (frag_size < hdr_len) {
                goto slow_path;
            }
        }
        pull_len = hdr_len;
    } else {
        ASSERT(gre_hdr != NULL);
    }

    gre_proto = ntohs(*(gre_hdr + 1));
    if (gre_proto != VR_GRE_PROTO_MPLS) {
        goto unhandled;
    }

    /* Take into consideration, the MPLS header and 4 bytes of
     * control information that might exist for L2 packet */
    if (frag_size < (pull_len + VR_MPLS_HDR_LEN + 
                            VR_L2_MCAST_CTRL_DATA_LEN))
        goto slow_path;

    label = ntohl(*(uint32_t *)(va + pull_len));
    control_data = *(uint32_t *)(va + pull_len + VR_MPLS_HDR_LEN);

    /* Identify whether the packet is L2 or not using the label and
     * control data */
    pkt_type = tunnel_type_cb(label, control_data, NULL);
    if (pkt_type <= 0)
        goto unhandled;

    if (pkt_type == PKT_MPLS_TUNNEL_L3) {
        /* L3 packet */
        iph = (struct vr_ip *) (va + pull_len + VR_MPLS_HDR_LEN);
        if (!vr_ip_is_ip6(iph)) {
            pull_len += VR_MPLS_HDR_LEN + sizeof(struct vr_ip);
        } else {
            pull_len += VR_MPLS_HDR_LEN + sizeof(struct vr_ip6);
            iph = NULL;
        }
    } else if (pkt_type == PKT_MPLS_TUNNEL_L2_MCAST) {
        /* L2 Multicast packet with control information and
         * Vxlan header. Vxlan header contains IP + UDP + Vxlan */
        l2_len = VR_VXLAN_HDR_LEN + VR_L2_MCAST_CTRL_DATA_LEN;
        eth = (struct vr_eth *)(va + pull_len + VR_MPLS_HDR_LEN + l2_len);

        pull_len += VR_MPLS_HDR_LEN + l2_len + sizeof(struct vr_eth);
    } else if ((pkt_type == PKT_MPLS_TUNNEL_L2_UCAST) ||
               (pkt_type == PKT_MPLS_TUNNEL_L2_MCAST_EVPN)) {
        /* L2 packet with no control information */
        eth = (struct vr_eth *)(va + pull_len + VR_MPLS_HDR_LEN);
        pull_len += VR_MPLS_HDR_LEN + sizeof(struct vr_eth);
    } else {
        goto unhandled;
    }

    if (frag_size < pull_len)
        goto slow_path;

    if (eth) {

        eth_proto = eth->eth_proto;
        l2_len += sizeof(struct vr_eth);
        while (ntohs(eth_proto) == VR_ETH_PROTO_VLAN) {
            eth_proto = ((struct vr_vlan_hdr *) (va + pull_len))->vlan_proto;
            pull_len += sizeof(struct vr_vlan_hdr);
            l2_len += sizeof(struct vr_vlan_hdr);
            if (frag_size < pull_len)
                goto slow_path;
        }

        if (ntohs(eth_proto) == VR_ETH_PROTO_IP) {
            iph = (struct vr_ip *)(va + pull_len);
            pull_len += sizeof(struct iphdr);
            if (frag_size < pull_len)
                goto slow_path;
        }

        if (ntohs(eth_proto) == VR_ETH_PROTO_ARP) {
            pull_len += sizeof(struct vr_arp);
            if (frag_size < pull_len)
                goto slow_path;
        }
    }

    if (iph) {
        thdr_valid = vr_ip_transport_header_valid(iph);
        if (thdr_valid) {
            /*
             * Account for IP options
             */
            hlen = iph->ip_hl * 4;
            pull_len += (hlen - sizeof(struct vr_ip));
            tcph_pull_len = pull_len;
            if (iph->ip_proto == VR_IP_PROTO_TCP) {
                pull_len += sizeof(struct tcphdr);
            } else if (iph->ip_proto == VR_IP_PROTO_UDP) {
                pull_len += sizeof(struct udphdr);
            } else if (iph->ip_proto == VR_IP_PROTO_ICMP) {
                pull_len += sizeof(struct icmphdr);
            }

            if (frag_size < pull_len) {
                goto slow_path;
            }
        
            if (iph->ip_proto == VR_IP_PROTO_TCP) {
                /*
                 * Account for TCP options
                 */
                tcph = (struct tcphdr *) ((char *) iph +  hlen);
                /*
                 * If SYN, send it to the slow path for possible TCP MSS adjust.
                 */
                if (tcph->syn && vr_to_vm_mss_adj) {
                    goto slow_path;
                }
                if ((tcph->doff << 2) > (sizeof(struct tcphdr))) {
                    pull_len += ((tcph->doff << 2) - (sizeof(struct tcphdr)));

                    if (frag_size < pull_len) {
                        goto slow_path;
                    }
                }
                th_csum = tcph->check;
            } else if (iph->ip_proto == VR_IP_PROTO_ICMP) {
                icmph = (struct vr_icmp *)((unsigned char *)iph + hlen);
                th_csum = icmph->icmp_csum;
                if (vr_icmp_error(icmph)) {
                    pull_len += sizeof(struct vr_ip);
                    if (frag_size < pull_len)
                        goto slow_path;
                    icmp_pl_iph = (struct vr_ip *)(icmph + 1);
                    pull_len += (icmp_pl_iph->ip_hl * 4) - sizeof(struct vr_ip);
                    if (frag_size < pull_len)
                        goto slow_path;
                    if (linux_ip_proto_pull((struct iphdr *)icmp_pl_iph)) {
                        pull_len -= sizeof(struct vr_icmp);
                        if (icmp_pl_iph->ip_proto == VR_IP_PROTO_TCP)
                            pull_len += sizeof(struct vr_tcp);
                        else if (icmp_pl_iph->ip_proto == VR_IP_PROTO_UDP)
                            pull_len += sizeof(struct vr_udp);
                        else
                            pull_len += sizeof(struct vr_icmp);

                        if (frag_size < pull_len)
                            goto slow_path;

                        if (icmp_pl_iph->ip_proto == VR_IP_PROTO_TCP) {
                            th_csum = ((struct vr_tcp *)
                                    ((unsigned char *)icmp_pl_iph +
                                     icmp_pl_iph->ip_hl * 4))->tcp_csum;
                        } else if (icmp_pl_iph->ip_proto == VR_IP_PROTO_UDP) {
                            th_csum = ((struct vr_udp *)
                                    ((unsigned char *)icmp_pl_iph +
                                     icmp_pl_iph->ip_hl * 4))->udp_csum;
                        } else if (icmp_pl_iph->ip_proto == VR_IP_PROTO_ICMP) {
                            th_csum = ((struct vr_icmp *)
                                    ((unsigned char *)icmp_pl_iph +
                                     icmp_pl_iph->ip_hl * 4))->icmp_csum;
                        }
                    }
                }
            } else if (iph->ip_proto == VR_IP_PROTO_UDP) {
                th_csum = ((struct udphdr *)
                        ((unsigned char *)iph + hlen))->check;
            }
        }
    }

    /* See whether we can accomodate the whole packet we are pulling to
     * linear skb */
    if ((skb->end - skb->tail) < pull_len) {
        goto slow_path;
    }

    memcpy(skb_tail_pointer(skb), va, pull_len);
    skb_frag_size_sub(frag, pull_len);
    frag->page_offset += pull_len;
    skb->data_len -= pull_len;
    skb->tail += pull_len;

    lh_reset_skb_fields(pkt);

    /*
     * Verify the checksum if the NIC didn't already do it. Only verify the
     * checksum if the inner packet is TCP as we only do GRO for TCP (and
     * GRO requires that checksum has been verified). For all other protocols,
     * we will let the guest verify the checksum if the outer header is
     * GRE. If the outer header is UDP, we will always verify the checksum
     * of the outer packet and this covers the inner packet too.
     */
    if (!skb_csum_unnecessary(skb)) {
        if (iph && !vr_ip_fragment(iph)) {
            if (iph->ip_proto == VR_IP_PROTO_TCP) {
                lh_handle_checksum_complete_skb(skb);

                if (skb_shinfo(skb)->nr_frags == 1) {
                    tcp_size = ntohs(iph->ip_len) - hlen;
                    if (lh_csum_verify_fast(iph, tcph, tcp_size)) {
                        if (th_csum == VR_DIAG_CSUM) {
                            vr_pkt_set_diag(pkt);
                        } else {
                            goto cksum_err;
                        }
                    }
                } else {
                    /*
                     * Pull to the start of the TCP header
                     */
                    skb_pull_len = (pkt_data(pkt) - skb->data) +
                        pkt_headlen + tcph_pull_len;

                    skb_pull(skb, skb_pull_len);
                    if (lh_csum_verify(skb, iph)) {
                        if (th_csum == VR_DIAG_CSUM) {
                            vr_pkt_set_diag(pkt);
                        } else {
                            goto cksum_err;
                        }
                    }
                    /*
                     * Restore the skb back to its original state. This is required
                     * as packets that get trapped to the agent assume that the skb
                     * is unchanged from the time it is received by vrouter.
                     */
                    skb_push(skb, skb_pull_len);
                }

                skb->ip_summed = CHECKSUM_UNNECESSARY;
            } else if (th_csum == VR_DIAG_CSUM) {
                vr_pkt_set_diag(pkt);
            }
        }
    } else if (th_csum == VR_DIAG_CSUM) {
        vr_pkt_set_diag(pkt);
    }

    if (pkt_type != PKT_MPLS_TUNNEL_L3 && skb->ip_summed ==
            CHECKSUM_PARTIAL)
        skb->ip_summed = CHECKSUM_UNNECESSARY;

    /* What we handled is only GRE header, so pull 
     * only the GRE header 
     */
    pkt_pull(pkt, hdr_len);


    if (va) {
        vr_kunmap_atomic(va);
    }

    *ret = PKT_RET_FAST_PATH;
    return 1;

unhandled:
    if (va) {
        vr_kunmap_atomic(va);
    }

    return 0;

cksum_err:
    if (va) {
        vr_kunmap_atomic(va);
    }

    *ret = PKT_RET_ERROR;
    return 1;

slow_path:
    if (va) {
        vr_kunmap_atomic(va);
    }

    *ret = PKT_RET_SLOW_PATH;
    return 1;
}

static int
lh_pkt_may_pull(struct vr_packet *pkt, unsigned int len)
{
    struct sk_buff *skb = vp_os_packet(pkt);
    unsigned int pull_len;

    pull_len = pkt->vp_data - skb_headroom(skb);
    pull_len += len;
    if (!pskb_may_pull(skb, pull_len))
        return -1;

    lh_reset_skb_fields(pkt);
    return 0;
}

/*
 * lh_pull_inner_headers_fast - faster version of lh_pull_inner_headers that
 * avoids multiple calls to pskb_may_pull(). In the common case, this
 * function should pull the inner headers into the linear part of the
 * skb and perform checksum verification. If it is not able to (because the
 * skb frags are not setup optimally), it will return PKT_RET_SLOW_PATH in
 * *ret and let a later call to lh_pull_inner_headers() do the required work.
 * Returns 1 if this is a packet that vrouter should handle, 0 otherwise.
 * The argument ret is set to PKT_RET_FAST_PATH on success, PKT_RET_ERROR
 * if there was an error and PKT_RET_SLOW_PATH if the packet needs to go
 * through the slow path (these are only applicable to the case where the
 * function returns 1). It also returns the encapsulation type which
 * identifies whether it is MPLS or VXLAN. Incase of MPLS encapsulation
 * it uses a call back function to identify whether it is unicast or
 * multicast
 */
static int
lh_pull_inner_headers_fast(struct vr_packet *pkt,
                           unsigned char proto, int
                           (*tunnel_type_cb)(unsigned int, unsigned int, 
                                                unsigned short *),
                           int *ret, int *encap_type)
{
    if (proto == VR_IP_PROTO_GRE) {
        return lh_pull_inner_headers_fast_gre(pkt, tunnel_type_cb, ret,
                encap_type);
    } else if (proto == VR_IP_PROTO_UDP) {
        return lh_pull_inner_headers_fast_udp(pkt, tunnel_type_cb, ret,
                encap_type);
    }

    return 0;
}


/*
 * lh_pull_inner_headers - given a pkt pointing at an outer header of length
 * hdr_len, pull in the MPLS header and as much of the inner packet headers
 * as required. 
 */
static int
lh_pull_inner_headers(struct vr_packet *pkt,
                      unsigned short ip_proto, unsigned short *reason,
                      int (*tunnel_type_cb)(unsigned int, unsigned int,
                          unsigned short *))
{
    int pull_len, hlen, hoff, ret = 0;
    struct sk_buff *skb = vp_os_packet(pkt); 
    struct vr_ip *iph = NULL, *icmp_pl_iph = NULL;
    unsigned short icmp_pl_ip_proto;
    struct tcphdr *tcph = NULL;
    struct vr_icmp *icmph = NULL;
    unsigned int tcpoff, skb_pull_len;
    bool thdr_valid = false, mpls_pkt = true, outer_cksum_validate;
    uint32_t label, control_data;
    struct vr_eth *eth = NULL;
    unsigned short hdr_len, vrouter_overlay_len, eth_proto, udph_cksum = 0;
    unsigned short th_csum = 0;
    struct udphdr *udph;
    struct vr_ip *outer_iph = NULL;

    *reason = VP_DROP_PULL;
    pull_len = 0;

    if (ip_proto == VR_IP_PROTO_GRE) {
        hdr_len = sizeof(struct vr_gre);
    } else if (ip_proto == VR_IP_PROTO_UDP) {
        hdr_len = sizeof(struct vr_udp);
    } else {
        goto error;
    }

    pull_len = hdr_len;
    pull_len += VR_MPLS_HDR_LEN + VR_L2_MCAST_CTRL_DATA_LEN;

    /*
     * vp_data is currently the offset of the start of the GRE/UDP header
     * from skb->head. Convert this to an offset from skb->data as this
     * is what pskb_may_pull() expects.
     */
    pull_len += (pkt->vp_data - (skb->data - skb->head));
    if (!pskb_may_pull(skb, pull_len)) {
        goto error;
    }

    vrouter_overlay_len = VROUTER_L2_OVERLAY_LEN;
    outer_cksum_validate = false;
    if (ip_proto == VR_IP_PROTO_UDP) {
       udph = (struct udphdr *)(skb->head + pkt->vp_data); 
       udph_cksum = udph->check;
       if (ntohs(udph->dest) != VR_MPLS_OVER_UDP_DST_PORT) {
           /*
            * we assumed earlier that the packet is mpls. now correct the
            * assumption
            */
           mpls_pkt = false;
           pull_len -= (VR_MPLS_HDR_LEN + VR_L2_MCAST_CTRL_DATA_LEN);
           pull_len += sizeof(struct vr_vxlan) + sizeof(struct vr_eth);
           if (!pskb_may_pull(skb, pull_len))
               goto error;
       }
    }

    if (mpls_pkt) {
        label = ntohl(*(uint32_t *)(skb->head + pkt->vp_data + hdr_len));
        hoff = pkt->vp_data + hdr_len + VR_MPLS_HDR_LEN;
        control_data = *(uint32_t *)(skb->head + hoff);

        if (!tunnel_type_cb) {
            *reason = VP_DROP_MISC;
            goto error;
        }

        ret = tunnel_type_cb(label, control_data, reason);

        /* Some issue with label. Just drop the packet, proper reason is
         * returned  */
        if (ret <= 0) 
            goto error;

        if (ret == PKT_MPLS_TUNNEL_L3) {
            /* L3 packet */

            pull_len = pull_len - VR_L2_MCAST_CTRL_DATA_LEN + 
                                                sizeof(struct vr_ip);
            if (!pskb_may_pull(skb, pull_len))
                goto error;
    
            hoff = pkt->vp_data + hdr_len + VR_MPLS_HDR_LEN;

            iph = (struct vr_ip *) (skb->head + hoff);
            if (vr_ip_is_ip6(iph))
                iph = NULL;
            vrouter_overlay_len = VROUTER_OVERLAY_LEN;
        } else if (ret == PKT_MPLS_TUNNEL_L2_MCAST) {

            /* L2 Multicast packet */
            pull_len += VR_VXLAN_HDR_LEN + sizeof(struct vr_eth);
            if (!pskb_may_pull(skb, pull_len))
                goto error;

            hoff += VR_L2_MCAST_CTRL_DATA_LEN + VR_VXLAN_HDR_LEN;
            eth = (struct vr_eth *) (skb->head + hoff);

        } else if ((ret == PKT_MPLS_TUNNEL_L2_UCAST) ||
                   (ret == PKT_MPLS_TUNNEL_L2_MCAST_EVPN)) {

            /* L2 unicast packet */
            pull_len = pull_len - VR_L2_MCAST_CTRL_DATA_LEN + 
                                        sizeof(struct vr_eth);
            if (!pskb_may_pull(skb, pull_len))
                goto error;

            eth = (struct vr_eth *) (skb->head + hoff);

        } else {
            *reason = VP_DROP_MISC;
            goto error;
        }
    } else {
        /* Ethernet header is already pulled as part of vxlan above */
        hoff = pkt->vp_data + hdr_len + sizeof(struct vr_vxlan);
        eth = (struct vr_eth *) (skb->head + hoff);
    }


    if (eth) {

        eth_proto = eth->eth_proto;
        hoff += sizeof(struct vr_eth);

        while (ntohs(eth_proto) == VR_ETH_PROTO_VLAN) {
            pull_len += sizeof(struct vr_vlan_hdr);
            if (!pskb_may_pull(skb, pull_len))
                goto error;
            eth_proto = ((struct vr_vlan_hdr *) (skb->head + hoff))->vlan_proto;
            hoff += sizeof(struct vr_vlan_hdr);
        }

        if (ntohs(eth_proto) == VR_ETH_PROTO_IP) {
            pull_len += sizeof(struct iphdr);
            if (!pskb_may_pull(skb, pull_len))
                goto error;
            iph = (struct vr_ip *) (skb->head + hoff);
        }

        if (ntohs(eth_proto) == VR_ETH_PROTO_ARP) {
            pull_len += sizeof(struct vr_arp);
            if (!pskb_may_pull(skb, pull_len))
                goto error;
        }
    }

    lh_reset_skb_fields(pkt);

    if (iph) {
        hlen = iph->ip_hl * 4;

        thdr_valid = vr_ip_transport_header_valid(iph);
        if (thdr_valid) {
            /*
             * Account for IP options, if present
             */
            pull_len += (hlen - sizeof(struct vr_ip));

            if (iph->ip_proto == VR_IP_PROTO_TCP) {
                pull_len += sizeof(struct tcphdr);
            } else if (iph->ip_proto == VR_IP_PROTO_UDP) {
                pull_len += sizeof(struct udphdr);
            } else if (iph->ip_proto == VR_IP_PROTO_ICMP) {
                pull_len += sizeof(struct icmphdr);
            }

            if (!pskb_may_pull(skb, pull_len))
                goto error;

            /*
             * pskb_may_pull could have freed and reallocated memory,
             * thereby invalidating the old iph pointer. Reinitialize it.
             */
            iph = (struct vr_ip *) (skb->head + hoff);

            /*
             * Account for TCP options, if present
             */
            if (iph->ip_proto == VR_IP_PROTO_TCP) {
                tcph = (struct tcphdr *) ((char *) iph +  hlen);
                if ((tcph->doff << 2) > (sizeof(struct tcphdr))) {
                    pull_len += ((tcph->doff << 2) - (sizeof(struct tcphdr)));
                    if (!pskb_may_pull(skb, pull_len))
                        goto error;

                    iph = (struct vr_ip *) (skb->head + hoff);
                    tcph = (struct tcphdr *) ((char *) iph +  hlen);
                }
                th_csum = tcph->check;
            } else if (iph->ip_proto == VR_IP_PROTO_ICMP) {
                icmph = (struct vr_icmp *)((unsigned char *)iph + hlen);
                th_csum = icmph->icmp_csum;
                if (vr_icmp_error(icmph)) {
                    pull_len += sizeof(struct vr_ip);
                    if (!pskb_may_pull(skb, pull_len))
                        goto error;
                    iph = (struct vr_ip *)(skb->head + hoff);
                    icmph = (struct vr_icmp *)((unsigned char *)iph + hlen);

                    icmp_pl_iph = (struct vr_ip *)(icmph + 1);
                    icmp_pl_ip_proto = icmp_pl_iph->ip_proto;
                    pull_len += (icmp_pl_iph->ip_hl * 4) - sizeof(struct vr_ip);
                    if (!pskb_may_pull(skb, pull_len))
                        goto error;

                    /* for source and target ports in the transport header */
                    pull_len += sizeof(struct vr_icmp);
                    if (skb->len < pull_len)
                        pull_len = skb->len;

                    if (!pskb_may_pull(skb, pull_len)) {
                        goto error;
                    }

                    pull_len -= sizeof(struct vr_icmp);
                    if (icmp_pl_ip_proto == VR_IP_PROTO_TCP)
                        pull_len += sizeof(struct vr_tcp);
                    else if (icmp_pl_ip_proto == VR_IP_PROTO_UDP)
                        pull_len += sizeof(struct vr_udp);
                    else
                        pull_len += sizeof(struct vr_icmp);

                    if (skb->len >= pull_len) {
                        if (pskb_may_pull(skb, pull_len)) {
                            iph = (struct vr_ip *)(skb->head + hoff);
                            icmph = (struct vr_icmp *)((unsigned char *)iph + hlen);
                            icmp_pl_iph = (struct vr_ip *)(icmph + 1);
                            if (icmp_pl_ip_proto == VR_IP_PROTO_TCP) {
                                th_csum = ((struct vr_tcp *)
                                        ((unsigned char *)icmp_pl_iph +
                                         icmp_pl_iph->ip_hl * 4))->tcp_csum;
                            } else if (icmp_pl_ip_proto == VR_IP_PROTO_UDP) {
                                th_csum = ((struct vr_udp *)
                                        ((unsigned char *)icmp_pl_iph +
                                         icmp_pl_iph->ip_hl * 4))->udp_csum;
                            } else if (icmp_pl_ip_proto == VR_IP_PROTO_ICMP) {
                                th_csum = ((struct vr_icmp *)
                                        ((unsigned char *)icmp_pl_iph +
                                         icmp_pl_iph->ip_hl * 4))->icmp_csum;
                            }
                        }
                    }

                    iph = (struct vr_ip *)(skb->head + hoff);
                }
            } else if (iph->ip_proto == VR_IP_PROTO_UDP) {
                th_csum = ((struct udphdr *)
                        ((unsigned char *)iph + hlen))->check;
            }
        }
        lh_reset_skb_fields(pkt);

        /*
         * FIXME - inner and outer IP header checksums should be verified
         * by vrouter, if required. Also handle cases where skb->ip_summed
         * is CHECKSUM_COMPLETE.
         */

         /*
          * Verify the checksum if the NIC didn't already do it. Only
          * verify the checksum if the inner packet is TCP as we only
          * do GRO for TCP (and GRO requires that checksum has been
          * verified). For all other protocols, we will let the
          * guest verify the checksum.
          */
         if (!skb_csum_unnecessary(skb)) {
             outer_iph = (struct vr_ip *)pkt_network_header(pkt);
             if (outer_iph && (outer_iph->ip_proto == VR_IP_PROTO_UDP) &&
                 udph_cksum) {
                 skb_pull_len = pkt_data(pkt) - skb->data;

                 skb_pull(skb, skb_pull_len);
                 if (lh_csum_verify_udp(skb, outer_iph)) {
                     if (th_csum == VR_DIAG_CSUM) {
                         vr_pkt_set_diag(pkt);
                     } else {
                         goto cksum_err;
                     }
                 }
                 /*
                  * Restore the skb back to its original state. This is
                  * required as packets that get trapped to the agent
                  * assume that the skb is unchanged from the time it
                  * is received by vrouter.
                  */
                 skb_push(skb, skb_pull_len);
                 if (tcph && vr_to_vm_mss_adj) {
                     lh_adjust_tcp_mss(tcph, skb, vrouter_overlay_len, sizeof(struct vr_ip));
                 }
             } else {
                 if (!vr_ip_fragment(iph)) {
                     if (iph->ip_proto == VR_IP_PROTO_TCP)  {
                         lh_handle_checksum_complete_skb(skb);
                         tcpoff = (char *)tcph - (char *) skb->data;

                         skb_pull(skb, tcpoff);
                         if (lh_csum_verify(skb, iph)) {
                             if (th_csum == VR_DIAG_CSUM) {
                                 vr_pkt_set_diag(pkt);
                             } else {
                                 goto cksum_err;
                             }
                         }

                         skb_push(skb, tcpoff);
                         if (vr_to_vm_mss_adj) {
                             lh_adjust_tcp_mss(tcph, skb, vrouter_overlay_len, sizeof(struct vr_ip));
                         }
                     } else if (th_csum == VR_DIAG_CSUM) {
                         vr_pkt_set_diag(pkt);
                     }
                 }
             }
         } else if (th_csum == VR_DIAG_CSUM) {
             vr_pkt_set_diag(pkt);
         }
    }

    /* If vxlan packet or (mpls and L2 packet) no checksum please */
    if ((!mpls_pkt || ret != PKT_MPLS_TUNNEL_L3) &&
                            skb->ip_summed == CHECKSUM_PARTIAL)
        skb->ip_summed = CHECKSUM_UNNECESSARY;


    return 1;

error:
    lh_reset_skb_fields(pkt);
    return 0;

cksum_err:
    lh_reset_skb_fields(pkt);
    *reason = VP_DROP_CKSUM_ERR;
    return 0;
}

static void *
lh_data_at_offset(struct vr_packet *pkt, unsigned short off)
{
    struct sk_buff *skb;
    struct sk_buff *frag;
    struct vr_packet *frag_pkt;

    if (off < pkt->vp_end)
        return pkt->vp_head + off;
    
    off = off - pkt->vp_end;
    skb = vp_os_packet(pkt);

    while (skb_shinfo(skb)->frag_list) {
        frag = skb_shinfo(skb)->frag_list;
        frag_pkt = (struct vr_packet *)frag->cb;
        if (off < frag_pkt->vp_end)
            return frag_pkt->vp_head + off;
        off -= frag_pkt->vp_end;
        skb = frag;
    }

    return NULL;
}

static void *
lh_network_header(struct vr_packet *pkt)
{
    struct sk_buff *skb;
    struct sk_buff *frag;
    struct vr_packet *frag_pkt;
    unsigned short off;

    if (pkt->vp_network_h < pkt->vp_end)
        return pkt->vp_head + pkt->vp_network_h;

    off = pkt->vp_network_h - pkt->vp_end;
    skb = vp_os_packet(pkt);

    while (skb_shinfo(skb)->frag_list) {
        frag = skb_shinfo(skb)->frag_list;
        frag_pkt = (struct vr_packet *)frag->cb;
        if (off < frag_pkt->vp_end)
            return frag_pkt->vp_head + off;
        off -= frag_pkt->vp_end;
        skb = frag;
    }

    return NULL;
}

static void
linux_timer(unsigned long arg)
{
    struct vr_timer *vtimer = (struct vr_timer *)arg;
    struct timer_list *timer = (struct timer_list *)vtimer->vt_os_arg;

    vtimer->vt_timer(vtimer->vt_vr_arg);
    mod_timer(timer, get_jiffies_64() + msecs_to_jiffies(vtimer->vt_msecs));

    return;
}

static void
lh_delete_timer(struct vr_timer *vtimer)
{
    struct timer_list *timer = (struct timer_list *)vtimer->vt_os_arg;

    if (timer) {
        del_timer_sync(timer);
        vr_free(vtimer->vt_os_arg);
        vtimer->vt_os_arg = NULL;
    }

    return;
}

static int
lh_create_timer(struct vr_timer *vtimer)
{
    struct timer_list *timer;

    timer = vr_zalloc(sizeof(*timer));
    if (!timer)
        return -ENOMEM;
    init_timer(timer);

    vtimer->vt_os_arg = (void *)timer;
    timer->data = (unsigned long)vtimer;
    timer->function = linux_timer;
    timer->expires = get_jiffies_64() + msecs_to_jiffies(vtimer->vt_msecs);
    timer->expires = get_jiffies_64() + msecs_to_jiffies(vtimer->vt_msecs);
    add_timer(timer);

    return 0;
}

struct host_os linux_host = {
    .hos_malloc                     =       lh_malloc,
    .hos_zalloc                     =       lh_zalloc,
    .hos_free                       =       lh_free,
    .hos_vtop                       =       lh_vtop,
    .hos_page_alloc                 =       lh_page_alloc,
    .hos_page_free                  =       lh_page_free,

    .hos_palloc                     =       lh_palloc,
    .hos_palloc_head                =       lh_palloc_head,
    .hos_pexpand_head               =       lh_pexpand_head,
    .hos_pfree                      =       lh_pfree,
    .hos_preset                     =       lh_preset,
    .hos_pclone                     =       lh_pclone,
    .hos_pcopy                      =       lh_pcopy,
    .hos_pfrag_len                  =       lh_pfrag_len,
    .hos_phead_len                  =       lh_phead_len,
    .hos_pset_data                  =       lh_pset_data,  
    .hos_pgso_size                  =       lh_pgso_size,

    .hos_get_cpu                    =       lh_get_cpu,
    .hos_schedule_work              =       lh_schedule_work,
    .hos_delay_op                   =       lh_delay_op,
    .hos_defer                      =       lh_defer,
    .hos_get_defer_data             =       lh_get_defer_data,
    .hos_put_defer_data             =       lh_put_defer_data,
    .hos_get_time                   =       lh_get_time,
    .hos_get_mono_time              =       lh_get_mono_time,
    .hos_create_timer               =       lh_create_timer,
    .hos_delete_timer               =       lh_delete_timer,

    .hos_network_header             =       lh_network_header,
    .hos_inner_network_header       =       lh_inner_network_header,
    .hos_data_at_offset             =       lh_data_at_offset,
    .hos_pheader_pointer            =       lh_pheader_pointer,
    .hos_pull_inner_headers         =       lh_pull_inner_headers,
    .hos_pcow                       =       lh_pcow,
    .hos_pull_inner_headers_fast    =       lh_pull_inner_headers_fast,
    .hos_get_udp_src_port           =       lh_get_udp_src_port,
    .hos_pkt_from_vm_tcp_mss_adj    =       lh_pkt_from_vm_tcp_mss_adj,
    .hos_pkt_may_pull               =       lh_pkt_may_pull,
};
    
struct host_os *
vrouter_get_host(void)
{
    return &linux_host;
}

static void
vr_message_exit(void)
{
    vr_genetlink_exit();
    vr_sandesh_exit();

    return;
}

static int
vr_message_init(void)
{
    int ret;

    ret = vr_sandesh_init();
    if (ret) {
        printk("%s:%d Sandesh initialization failed with return %d\n",
                __FUNCTION__, __LINE__, ret);
        return ret;
    }

    ret = vr_genetlink_init();
    if (ret) {
        printk("%s:%d Generic Netlink initialization failed with return %d\n",
                __FUNCTION__, __LINE__, ret);
        goto init_fail;
    }

    return 0;

init_fail:
    vr_message_exit();
    return ret;
}

/*
 * sysctls to control vrouter functionality and for debugging
 */
static struct ctl_path vrouter_path[] =
{
    {.procname = "net", },
    {.procname = "vrouter", },
    { }
};

static ctl_table vrouter_table[] =
{
    {
        .procname       = "perfr",
        .data           = &vr_perfr,
        .maxlen         = sizeof(int),
        .mode           = 0644,
        .proc_handler   = proc_dointvec,
    },
    {
        .procname       = "mudp",
        .data           = &vr_mudp,
        .maxlen         = sizeof(int),
        .mode           = 0644,
        .proc_handler   = proc_dointvec,
    },
    {
        .procname       = "perfs",
        .data           = &vr_perfs,
        .maxlen         = sizeof(int),
        .mode           = 0644,
        .proc_handler   = proc_dointvec,
    },
    {
        .procname       = "perfp",
        .data           = &vr_perfp,
        .maxlen         = sizeof(int),
        .mode           = 0644,
        .proc_handler   = proc_dointvec,
    },
    {
        .procname       = "r1",
        .data           = &vr_perfr1,
        .maxlen         = sizeof(int),
        .mode           = 0644,
        .proc_handler   = proc_dointvec,
    },
    {
        .procname       = "r2",
        .data           = &vr_perfr2,
        .maxlen         = sizeof(int),
        .mode           = 0644,
        .proc_handler   = proc_dointvec,
    },
    {
        .procname       = "r3",
        .data           = &vr_perfr3,
        .maxlen         = sizeof(int),
        .mode           = 0644,
        .proc_handler   = proc_dointvec,
    },
    {
        .procname       = "q1",
        .data           = &vr_perfq1,
        .maxlen         = sizeof(int),
        .mode           = 0644,
        .proc_handler   = proc_dointvec,
    },
    {
        .procname       = "q2",
        .data           = &vr_perfq2,
        .maxlen         = sizeof(int),
        .mode           = 0644,
        .proc_handler   = proc_dointvec,
    },
    {
        .procname       = "q3",
        .data           = &vr_perfq3,
        .maxlen         = sizeof(int),
        .mode           = 0644,
        .proc_handler   = proc_dointvec,
    },
    {
        .procname       = "from_vm_mss_adj",
        .data           = &vr_from_vm_mss_adj,
        .maxlen         = sizeof(int),
        .mode           = 0644,
        .proc_handler   = proc_dointvec,
    },
    {
        .procname       = "to_vm_mss_adj",
        .data           = &vr_to_vm_mss_adj,
        .maxlen         = sizeof(int),
        .mode           = 0644,
        .proc_handler   = proc_dointvec,
    },
    {
        .procname       = "udp_coff",
        .data           = &vr_udp_coff,
        .maxlen         = sizeof(int),
        .mode           = 0644,
        .proc_handler   = proc_dointvec,
    },
    {}
};

struct ctl_table_header *vr_sysctl_header = NULL;

static void
vr_sysctl_exit(void)
{
    if (vr_sysctl_header) {
        unregister_sysctl_table(vr_sysctl_header);
        vr_sysctl_header = NULL;
    }

    return;
}

static void
vr_sysctl_init(void)
{
    if (vr_sysctl_header == NULL) {
        vr_sysctl_header = register_sysctl_paths(vrouter_path, vrouter_table);
        if (vr_sysctl_header == NULL) {
            printk("vrouter sysctl registration failed\n");
        }
    }

    return;
}

static void
vrouter_linux_exit(void)
{
    vr_sysctl_exit();
    vr_message_exit();
    vr_mem_exit();
    vrouter_exit(false);
    flush_scheduled_work();
    rcu_barrier();
    return;
}


static int __init
vrouter_linux_init(void)
{
    int ret;

	printk("vrouter version: %s\n", VROUTER_VERSIONID);
    vr_num_cpus = num_present_cpus() & VR_CPU_MASK;
    if (!vr_num_cpus) {
        printk("%s:%d Failed to get number of CPUs\n",
                __FUNCTION__, __LINE__);
        return -1;
    }

    ret = vrouter_init();
    if (ret)
        return ret;

    ret = vr_mem_init();
    if (ret)
        goto init_fail;

    ret = vr_message_init();
    if (ret)
        goto init_fail;

    vr_sysctl_init();

    return 0;

init_fail:
    vrouter_linux_exit();
    return ret;
}

module_param(vr_flow_entries, int, 0);
module_param(vr_oflow_entries, int, 0);

module_param(vr_bridge_entries, int, 0);
module_param(vr_bridge_oentries, int, 0);

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
module_param(vr_use_linux_br, int, 0);
#endif

module_param(vrouter_dbg, int, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(vrouter_dbg, "Set 1 for pkt dumping and 0 to disable, default value is 0");

module_init(vrouter_linux_init);
module_exit(vrouter_linux_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION(VROUTER_VERSIONID);
