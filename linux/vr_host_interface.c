/*
 * vr_host_interface.c -- linux specific handling of vrouter interfaces
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <linux/init.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/jhash.h>
#include <linux/pkt_sched.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39))
#include <linux/if_bridge.h>
#include <linux/openvswitch.h>
#endif

#include <net/rtnetlink.h>
#include "vrouter.h"
#include "vr_packet.h"
#include "vr_compat.h"
#include "vr_interface.h"
#include "vr_linux.h"
#include "vr_bridge.h"
#include "vr_os.h"
#include "vhost.h"
#include "vr_datapath.h"

extern int vhost_init(void);
extern void vhost_exit(void);
extern void vhost_if_add(struct vr_interface *);
extern void vhost_if_del(struct net_device *);
extern void vhost_if_del_phys(struct net_device *);
extern void lh_pfree_skb(struct sk_buff *, struct vr_interface *, unsigned short);
extern int vr_gro_vif_add(struct vrouter *, unsigned int, char *, unsigned short);
extern struct vr_interface_stats *vif_get_stats(struct vr_interface *,
        unsigned short);

static int vr_napi_poll(struct napi_struct *, int);
static rx_handler_result_t pkt_gro_dev_rx_handler(struct sk_buff **);
static int linux_xmit_segments(struct vr_interface *, struct sk_buff *,
        unsigned short);
static rx_handler_result_t pkt_rps_dev_rx_handler(struct sk_buff **pskb);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
extern rx_handler_result_t vhost_rx_handler(struct sk_buff **);
#else
struct vr_interface vr_reset_interface;
#endif

extern volatile bool agent_alive;

/*
 * Structure to store information required to be sent across CPU cores
 * when RPS is performed on the physical interface (vr_perfr3 is 1).
 */
typedef struct vr_rps_ {
    unsigned int vif_idx;
    unsigned short vif_rid;
} vr_rps_t;

/*
 *  pkt_gro_dev - this is a device used to do receive offload on packets
 *  destined over a TAP interface to a VM.
 */
static struct net_device *pkt_gro_dev = NULL;

/*
 *  pkt_l2_gro_dev - this is a device used to do receive offload on L2 packets
 *  destined over a TAP interface to a VM.
 */
static struct net_device *pkt_l2_gro_dev = NULL;

/*
 * pkt_gro_dev_ops - netdevice operations on GRO packet device. Currently,
 * no operations are needed, but an empty structure is required to
 * register the device.
 *
 */
static struct net_device_ops pkt_gro_dev_ops;

/*
 * pkt_rps_dev - this is a device used to perform RPS on packets coming in
 * on a physical interface.
 */
static struct net_device *pkt_rps_dev = NULL;

/*
 * pkt_rps_dev_ops - netdevice operations on RPS packet device. Currently,
 * no operations are needed, but an empty structure is required to
 * register the device.
 *
 */
static struct net_device_ops pkt_rps_dev_ops;

/*
 * vr_skb_set_rxhash - set the rxhash on a skb if the kernel version
 * allows it.
 */
void
vr_skb_set_rxhash(struct sk_buff *skb, __u32 val)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
#if defined(RHEL_MAJOR) && defined(RHEL_MINOR) && \
           (RHEL_MAJOR == 6) && (RHEL_MINOR >= 4)
    skb->rxhash = val;
#endif
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0))
#if defined(RHEL_MAJOR) && defined(RHEL_MINOR) && \
           (RHEL_MAJOR == 7) && (RHEL_MINOR >= 2)
    skb->hash = val;
#else
    skb->rxhash = val;
#endif
#else
    skb->hash = val;
#endif
}

/*
 * vr_skb_get_rxhash - get the rxhash on a skb if the kernel version
 * allows it.
 */
__u32
vr_skb_get_rxhash(struct sk_buff *skb)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
#if defined(RHEL_MAJOR) && defined(RHEL_MINOR) && \
           (RHEL_MAJOR == 6) && (RHEL_MINOR >= 4)
    return skb->rxhash;
#elif
    return skb->hash;
#else
    return 0;
#endif
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0))
#if defined(RHEL_MAJOR) && defined(RHEL_MINOR) && \
           (RHEL_MAJOR == 7) && (RHEL_MINOR >= 2)
    return skb->hash;
#else
    return skb->rxhash;
#endif
#else
    return skb->hash;
#endif
}

static inline struct sk_buff*
linux_skb_vlan_insert(struct vr_interface *vif, struct sk_buff *skb,
                      unsigned short vlan_id)
{
    struct vlan_ethhdr *veth;

    if (skb_cow_head(skb, VLAN_HLEN) < 0) {
        lh_pfree_skb(skb, vif, VP_DROP_MISC);
        return NULL;
    }

    veth = (struct vlan_ethhdr *)skb_push(skb, VLAN_HLEN);

    /* Move the mac addresses to the beginning of the new header. */
    memmove(skb->data, skb->data + VLAN_HLEN, 2 * ETH_ALEN);
    skb->mac_header -= VLAN_HLEN;

    /* first, the ethernet type */
    veth->h_vlan_proto = htons(ETH_P_8021Q);

    /* now, the TCI */
    veth->h_vlan_TCI = htons(vlan_id);

    skb_reset_mac_header(skb);
    skb_reset_mac_len(skb);

    return skb;
}

static int
linux_if_rx(struct vr_interface *vif, struct vr_packet *pkt)
{
    int rc;
    struct net_device *dev = (struct net_device *)vif->vif_os;
    struct sk_buff *skb = vp_os_packet(pkt);
    struct vr_ip *ip;
    unsigned short network_off, transport_off, cksum_off = 0;

    skb->data = pkt->vp_head + pkt->vp_data;
    skb->len = pkt_len(pkt);
    skb_set_tail_pointer(skb, pkt_head_len(pkt));

    skb->queue_mapping = pkt->vp_queue;
    skb->priority = pkt->vp_priority;

    if (!dev) {
        vif_drop_pkt(vif, pkt, false);
        goto exit_rx;
    }

    (void)__sync_fetch_and_add(&dev->stats.rx_bytes, skb->len);
    (void)__sync_fetch_and_add(&dev->stats.rx_packets, 1);

    /* this is only needed for mirroring */
    if ((pkt->vp_flags & VP_FLAG_FROM_DP) &&
            (pkt->vp_flags & VP_FLAG_CSUM_PARTIAL)) {
    	network_off = pkt_get_network_header_off(pkt);
    	ip = (struct vr_ip *)(pkt_data_at_offset(pkt, network_off));
    	transport_off = network_off + (ip->ip_hl * 4);

        if (ip->ip_proto == VR_IP_PROTO_TCP)
            cksum_off = offsetof(struct vr_tcp, tcp_csum);
        else if (ip->ip_proto == VR_IP_PROTO_UDP)
            cksum_off = offsetof(struct vr_udp, udp_csum);
 
        if (cksum_off)
            *(unsigned short *)
                (pkt_data_at_offset(pkt, transport_off + cksum_off))
                = 0;
    }

    skb->protocol = eth_type_trans(skb, dev);
    skb->pkt_type = PACKET_HOST;
    rc = netif_rx(skb);

exit_rx:
    return RX_HANDLER_CONSUMED;
}

struct vrouter_gso_cb {
    void (*destructor)(struct sk_buff *skb);
};

static long
linux_inet_fragment(struct vr_interface *vif, struct sk_buff *skb,
        unsigned short type)
{
    struct iphdr *ip = ip_hdr(skb);
    unsigned int ip_hlen = ip->ihl * 4;
    bool fragmented = ntohs(ip->frag_off) & IP_MF ? true : false;
    unsigned int offset = (ntohs(ip->frag_off) & IP_OFFSET) << 3;
    unsigned short ip_id = ntohs(ip->id);
    unsigned int payload_size = skb->len - skb->mac_len - ip_hlen;
    unsigned int frag_size = skb->dev->mtu - skb->mac_len - ip_hlen;
    unsigned int num_frags, last_frag_len;
    struct sk_buff *segs;
    netdev_features_t features;

    features = netif_skb_features(skb);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
    features &= (~(NETIF_F_ALL_TSO | NETIF_F_UFO | NETIF_F_GSO));
#else
    features &= ~(NETIF_F_TSO | NETIF_F_UFO | NETIF_F_GSO);
#endif
    /*
     * frag size has to be a multiple of 8 and last fragment has
     * to be >= 64 bytes (approx)
     */
    frag_size &= ~7U;
    num_frags = payload_size / frag_size;
    last_frag_len = payload_size % frag_size;
    if (last_frag_len && last_frag_len < 64) {
        frag_size -= ((64 - last_frag_len) / num_frags);
        /*
         * the previous division could have produced 0. to cover
         * that case make some change to frag_size
         */
        frag_size -= 1;
        /* by doing this, we will get 8 bytes in the worst case */
        frag_size &= ~7U;
    }

    skb_shinfo(skb)->gso_size = 0;

    /*
     * for packets that need checksum help, checksum has to be
     * calculated here, since post fragmentation, checksum of
     * individual fragments will be wrong
     */
    if (skb->ip_summed == CHECKSUM_PARTIAL) {
        if (skb_checksum_help(skb)) {
            lh_pfree_skb(skb, vif, VP_DROP_MISC);
            return 0;
        }
    }

    skb_shinfo(skb)->gso_size = frag_size;

    /* pull till transport header */
    skb_pull(skb, skb->mac_len + ip_hlen);
    /*
     * in 2.6.32-358.123.2.openstack.el6 kernel (and I guess all openstack
     * kernels), the first field in the skb->cb is an offset field that is
     * used to calculate header length. In those kernels, skb->cb is a
     * structure of type skb_gso_cb with one field. Need to set that field
     * to zero.
     *
     * This is equivalent to doing
     *
     * pkt->vp_head = NULL
     *
     * and hence access to packet structure beyond this point is suicidal
     */
    memset(skb->cb, 0, sizeof(skb->cb));
    segs = skb_segment(skb, features);
    if (IS_ERR(segs))
        return PTR_ERR(segs);

    kfree_skb(skb);
    skb = segs;
    do {
        ip = ip_hdr(skb);
        ip->id = htons(ip_id);
        ip->frag_off = htons(offset >> 3);
        if (skb->next != NULL || fragmented)
            ip->frag_off |= htons(IP_MF);
        offset += (skb->len - skb->mac_len - ip->ihl * 4);
        ip->tot_len = htons(skb->len - skb->mac_len);
        ip->check = 0;
        ip->check = ip_fast_csum(skb_network_header(skb), ip->ihl);
    } while ((skb = skb->next));


    return linux_xmit_segments(vif, segs, type);
}

static int
linux_xmit(struct vr_interface *vif, struct sk_buff *skb,
        unsigned short type)
{
    if (vif->vif_type == VIF_TYPE_VIRTUAL &&
            skb->ip_summed == CHECKSUM_NONE)
        skb->ip_summed = CHECKSUM_UNNECESSARY;

    if ((type == VP_TYPE_IPOIP) &&
            (skb->len > skb->dev->mtu + skb->dev->hard_header_len))
        return linux_inet_fragment(vif, skb, type);

    return dev_queue_xmit(skb);
}

static int
linux_xmit_segment(struct vr_interface *vif, struct sk_buff *seg,
        unsigned short type, int diag)
{
    int err = -ENOMEM;
    unsigned short iphlen, ethlen;
    unsigned short eth_proto, reason = 0;
    unsigned int num_vlan_hdrs = 0;

    struct vr_eth *eth;
    struct vr_vlan_hdr *vlan;
    struct vr_ip *iph, *i_iph = NULL;
    struct udphdr *udph;

    /* we will do tunnel header updates after the fragmentation */
    if (seg->len > seg->dev->mtu + seg->dev->hard_header_len
            || !vr_pkt_type_is_overlay(type)) {
        return linux_xmit(vif, seg, type);
    }

    if (seg->dev->type == ARPHRD_ETHER) {
        ethlen = ETH_HLEN;
    } else {
        ethlen = 0;
    }

    if (!pskb_may_pull(seg, ethlen + sizeof(struct vr_ip))) {
        reason = VP_DROP_PULL;
        goto exit_xmit;
    }

    if (ethlen) {
        eth = (struct vr_eth *)(seg->data);
        eth_proto = eth->eth_proto;
        while (eth_proto == htons(VR_ETH_PROTO_VLAN)) {
            if (num_vlan_hdrs > 3) {
                reason = VP_DROP_INVALID_PROTOCOL;
                goto exit_xmit;
            }

            num_vlan_hdrs++;
            vlan = (struct vr_vlan_hdr *)(seg->data + ethlen);
            eth_proto = vlan->vlan_proto;
            ethlen += sizeof(struct vr_vlan_hdr);
        }

        if (!pskb_may_pull(seg, ethlen + sizeof(struct vr_ip))) {
            reason = VP_DROP_PULL;
            goto exit_xmit;
        }
    }

    iph = (struct vr_ip *)(seg->data + ethlen);
    iphlen = (iph->ip_hl << 2);
    if (!pskb_may_pull(seg, ethlen + iphlen)) {
        reason = VP_DROP_PULL;
        goto exit_xmit;
    }
    iph = (struct vr_ip *)(seg->data + ethlen);
    iph->ip_len = htons(seg->len - ethlen);

    if (type == VP_TYPE_IPOIP)
        i_iph = (struct vr_ip *)skb_network_header(seg);

    /*
     * it is important that we copy the inner network header's
     * ip id to outer. For now, agent diagnostics (traceroute)
     * depends on this behavior.
     */
    if (i_iph)
        iph->ip_id = i_iph->ip_id;
    else
        iph->ip_id = htons(vr_generate_unique_ip_id());

    iph->ip_csum = 0;
    iph->ip_csum = ip_fast_csum(iph, iph->ip_hl);

    if (iph->ip_proto == VR_IP_PROTO_UDP) {
        if (!pskb_may_pull(seg, ethlen + iphlen +
                    sizeof(struct udphdr))) {
            reason = VP_DROP_PULL;
            goto exit_xmit;
        }

        if (vr_udp_coff && !diag) {
            skb_set_network_header(seg, ethlen);
            iph->ip_csum = 0;

            skb_set_transport_header(seg,  iphlen + ethlen);
            if (!skb_partial_csum_set(seg, skb_transport_offset(seg),
                        offsetof(struct udphdr, check))) {
                reason = VP_DROP_MISC;
                goto exit_xmit;
            }

            udph = (struct udphdr *) skb_transport_header(seg);
            udph->len = htons(seg->len - skb_transport_offset(seg));
            iph->ip_csum = ip_fast_csum(iph, iph->ip_hl);
            udph->check = ~csum_tcpudp_magic(iph->ip_saddr, iph->ip_daddr,
                                             htons(udph->len),
                                             IPPROTO_UDP, 0);

        } else {
            /*
             * If we are encapsulating a L3/L2 packet in UDP, set the UDP
             * checksum to 0 and let the NIC calculate the checksum of the
             * inner packet (if the NIC supports it).
             */
            udph = (struct udphdr *) (((char *)iph) + iphlen);
            udph->len = htons(seg->len - (ethlen + iphlen));
            udph->check = 0;

            iph->ip_csum = 0;
            iph->ip_csum = ip_fast_csum(iph, iph->ip_hl);

            if ((vif->vif_flags & VIF_FLAG_TX_CSUM_OFFLOAD) == 0) {
                if (seg->ip_summed == CHECKSUM_PARTIAL) {
                    skb_checksum_help(seg);
                }
            }
        }
    } else if (iph->ip_proto == VR_IP_PROTO_GRE) {
        if ((vif->vif_flags & VIF_FLAG_TX_CSUM_OFFLOAD) == 0) {
            if (seg->ip_summed == CHECKSUM_PARTIAL) {
                skb_checksum_help(seg);
            }
        }
    }

    return linux_xmit(vif, seg, type);

exit_xmit:
    lh_pfree_skb(seg, vif, reason);
    return err;
}

static int
linux_xmit_segments(struct vr_interface *vif, struct sk_buff *segs,
        unsigned short type)
{
    int err;
    struct sk_buff *nskb = NULL;

    do {
        nskb = segs->next;
        segs->next = NULL;
        if ((err = linux_xmit_segment(vif, segs, type, 0)))
            break;
        segs = nskb;
    } while (segs);

    segs = nskb;
    while (segs) {
        nskb = segs->next;
        segs->next = NULL;
        kfree_skb(segs);
        segs = nskb;
    }

    return err;
}

/*
 * linux_gso_xmit - perform segmentation of the inner packet in software
 * and send each segment out the wire after fixing the outer header.
 */
static void
linux_gso_xmit(struct vr_interface *vif, struct sk_buff *skb,
        unsigned short type)
{
    netdev_features_t features;
    struct sk_buff *segs;
    unsigned short seg_size = skb_shinfo(skb)->gso_size;
    struct iphdr *ip = ip_hdr(skb);
    struct tcphdr *th;
    struct net_device *ndev = (struct net_device *)vif->vif_os;

    features = netif_skb_features(skb);
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
    features &= (~(NETIF_F_ALL_TSO | NETIF_F_UFO | NETIF_F_GSO));
#else
    features &= (~(NETIF_F_TSO | NETIF_F_UFO | NETIF_F_GSO));
#endif
    seg_size += skb->mac_len + skb_network_header_len(skb);
    /*
     * We are trying to find whether the total size of the packet will
     * overshoot the mtu. Above, we have accounted for the tunnel headers,
     * the inner ip header, and the segment size. However, there is a
     * subtle difference in deciding whether transport header is part of
     * GSO size or not.
     *
     * For TCP, segment size (gso size) is the ip data length - tcp header
     * length (since each segment goes with tcp header), while for udp, there
     * are only fragments (and no segments) and the segment size (fragment
     * size) is the ip data length adjusted to mtu (since udp header goes
     * only with the first fragment). Hence the following condition
     */
    if (ip->protocol == IPPROTO_TCP) {
        th = tcp_hdr(skb);
        seg_size += (th->doff * 4);
    }

    /*
     * avoid fragmentation after segmentation. 
     */ 
    if (seg_size > ndev->mtu + ndev->hard_header_len) {
        skb_shinfo(skb)->gso_size -= (seg_size - ndev->mtu -
                ndev->hard_header_len);
        if (ip->protocol == IPPROTO_UDP)
            skb_shinfo(skb)->gso_size &= ~7;
    }

    segs = skb_gso_segment(skb, features);
    kfree_skb(skb);
    if ((IS_ERR(segs)) || (segs == NULL)) {
        return;
    }

    linux_xmit_segments(vif, segs, type);

    return;
}

#ifdef CONFIG_RPS

/*
 * linux_get_rxq - get a receive queue for the packet on an interface that
 * has RPS enabled. The receive queue is picked such that it is different
 * from the current CPU core and the previous CPU core that handled the
 * packet (if the previous core is specified). The receive queue has a 1-1
 * mapping to the receiving CPU core (i.e. queue 1 corresponds to CPU core 0,
 * queue 2 to CPU core 1 and so on). The CPU core is chosen such that it is
 * on the same NUMA node as the  current core (to minimize memory access
 * latency across NUMA nodes), except that hyper-threads of the current
 * and previous core are excluded as choices for the next CPU to process the
 * packet.
 */
static void
linux_get_rxq(struct sk_buff *skb, u16 *rxq, unsigned int curr_cpu,
              unsigned int prev_cpu)
{
    unsigned int next_cpu;
    int numa_node = cpu_to_node(curr_cpu);
    const struct cpumask *node_cpumask = cpumask_of_node(numa_node);
    struct cpumask noht_cpumask;
    unsigned int num_cpus, cpu, count = 0;
    __u32 rxhash;

    /*
     * We are running in softirq context, so CPUs can't be offlined
     * underneath us. So, it is safe to use the NUMA node CPU bitmaps.
     * Clear the bits corresponding to the current core and its hyperthreads
     * in the node CPU mask.
     */
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4,2,0))
    cpumask_andnot(&noht_cpumask, node_cpumask, cpu_sibling_mask(curr_cpu));
#else
    cpumask_andnot(&noht_cpumask, node_cpumask,
                   topology_sibling_cpumask(curr_cpu));
#endif

    /*
     * If the previous CPU is specified, clear the bits corresponding to
     * that core and its hyperthreads in the CPU mask.
     */
    if (prev_cpu && (prev_cpu <= nr_cpu_ids)) {
        cpumask_andnot(&noht_cpumask, &noht_cpumask,
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4,2,0))
                       cpu_sibling_mask(prev_cpu-1));
#else
                       topology_sibling_cpumask(prev_cpu-1));
#endif
    }

    num_cpus = cpumask_weight(&noht_cpumask);

    if (num_cpus) {
        rxhash = skb_get_hash(skb);
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32)) 
        next_cpu = ((u32)rxhash * num_cpus) >> 16;
#else
        next_cpu = ((u64)rxhash * num_cpus) >> 32;
#endif

        /*
         * next_cpu is between 0 and (num_cpus - 1). Find the CPU corresponding
         * to next_cpu in the CPU bitmask.
         */
        for_each_cpu(cpu, &noht_cpumask) {
            if (count == next_cpu) {
                break;
            }

            count++;
        }

        if (cpu >= nr_cpu_ids) {
            /*
             * Shouldn't happen
             */
            *rxq = curr_cpu;
        } else {
            *rxq = cpu;
        }
    } else {
        /*
         * Not enough CPU cores available in this NUMA node. Continue
         * processing the packet on the same CPU core.
         */
        *rxq = curr_cpu;
    }

    return;
}   

#endif

/*
 * linux_enqueue_pkt_for_gro - enqueue packet on a list of skbs and schedule a
 * NAPI event on the NAPI structure of the vif.
 *
 */
void
linux_enqueue_pkt_for_gro(struct sk_buff *skb, struct vr_interface *vif,
                          bool l2_pkt)
{
    struct vr_interface *gro_vif;
    struct vr_interface_stats *gro_vif_stats;
    int in_intr_context;
    struct sk_buff_head *head;
    struct napi_struct *napi;


    if (l2_pkt) {
        skb->dev = pkt_l2_gro_dev;
        gro_vif = pkt_l2_gro_dev->ml_priv;
        head = &vif->vr_skb_l2_inputq;
        napi = &vif->vr_l2_napi;
    } else {
        skb->dev = pkt_gro_dev;
        gro_vif = pkt_gro_dev->ml_priv;
        head = &vif->vr_skb_inputq;
        napi = &vif->vr_napi;
    }

    if (gro_vif) {
        gro_vif_stats = vif_get_stats(gro_vif, vr_get_cpu());
        if (gro_vif_stats) {
            gro_vif_stats->vis_opackets++;
            gro_vif_stats->vis_obytes += skb->len;
        }
    }
    skb_queue_tail(head, skb);

    /*
     * napi_schedule may raise a softirq, so if we are not already in
     * interrupt context (which is the case when we get here as a result of 
     * the agent enabling a flow for forwarding), ensure that the softirq is 
     * handled immediately.
     */
    in_intr_context = in_interrupt();
    if (!in_intr_context) {
        local_bh_disable();
    }

    napi_schedule(napi);

    if (!in_intr_context) {
        local_bh_enable();
    }

    return;
}

#if 0
static void __skb_dump_info(const char *prefix, const struct sk_buff *skb,
	struct vr_interface *vif)
{
#ifdef CONFIG_XEN
    int i, nr = skb_shinfo(skb)->nr_frags;
#endif
    struct ethhdr *ethh = eth_hdr(skb);
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;

    printk("vif info: type=%d id=%d os_id=%d\n",
            vif->vif_type, vif->vif_idx, vif->vif_os_idx);

    printk(KERN_CRIT "%s: len is %#x (data:%#x mac:%#x) truesize %#x\n", prefix,
            skb->len, skb->data_len, skb->mac_len, skb->truesize);

    printk(KERN_CRIT "%s: linear:%s\n", prefix,
            skb_is_nonlinear(skb) ? "No" : "Yes");
    printk(KERN_CRIT "%s: data %p head %p tail %p end %p\n", prefix,
            skb->data, skb->head, skb->tail, skb->end);
    printk(KERN_CRIT "%s: flags are local_df:%d cloned:%d ip_summed:%d"
            "nohdr:%d\n", prefix, skb->local_df, skb->cloned,
            skb->ip_summed, skb->nohdr);
    printk(KERN_CRIT "%s: nfctinfo:%d pkt_type:%d fclone:%d ipvs_property:%d\n",
            prefix, skb->nfctinfo, skb->pkt_type,
            skb->nohdr, skb->ipvs_property);
    printk(KERN_CRIT "%s: shared info %p ref %#x\n", prefix,
            skb_shinfo(skb), atomic_read(&skb_shinfo(skb)->dataref));
    printk(KERN_CRIT "%s: frag_list %p\n", prefix,
            skb_shinfo(skb)->frag_list);

    if (ethh) {
        printk(KERN_CRIT "%s: eth: (%p) src:%pM dest:%pM proto %u\n",
                prefix, ethh, ethh->h_source, ethh->h_dest, ntohs(ethh->h_proto));
        if (ethh->h_proto == __constant_htons(ETH_P_IP))
            iph = ip_hdr(skb);
        } else
            printk(KERN_CRIT "%s: eth: header not present\n", prefix);

    if (iph) {
        printk(KERN_CRIT "%s: ip: (%p) saddr "NIPQUAD_FMT" daddr "NIPQUAD_FMT"\
             protocol %d frag_off %d\n", prefix, iph, NIPQUAD(iph->saddr),
             NIPQUAD(iph->daddr), iph->protocol, iph->frag_off);

        if (iph->protocol == IPPROTO_TCP)
            tcph = tcp_hdr(skb);
    } else
        printk(KERN_CRIT "%s: ip: header not present\n", prefix);

    if (tcph) {
        printk(KERN_CRIT "%s: tcp: (%p) source %d dest %d seq %u ack %u\n",
                prefix, tcph, ntohs(tcph->source), ntohs(tcph->dest),
                ntohl(tcph->seq), ntohl(tcph->ack_seq));
    } else
        printk(KERN_CRIT "%s: tcp: header not present\n", prefix);

#ifdef CONFIG_XEN
    printk(KERN_CRIT "%s: nr_frags %d\n", prefix, nr);
    for(i=0; i<nr; i++) {
        skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
        unsigned long pfn = page_to_pfn(frag->page);
        unsigned long mfn = pfn_to_mfn(pfn);
        printk(KERN_CRIT "%s: %d/%d page:%p count:%d offset:%#x size:%#x \
                virt:%p pfn:%#lx mfn:%#lx%s flags:%lx%s%s)\n",
                prefix, i + 1, nr, frag->page,
                atomic_read(&frag->page->_count),
                frag->page_offset, frag->size,
                phys_to_virt(page_to_pseudophys(frag->page)), pfn, mfn,
                phys_to_machine_mapping_valid(pfn) ? "" : "(BAD)",
                frag->page->flags,
                PageForeign(frag->page) ? " FOREIGN" : "",
                PageBlkback(frag->page) ? " BLKBACK" : "");
    }
#endif
}
#endif

static int
linux_if_tx(struct vr_interface *vif, struct vr_packet *pkt)
{
    struct net_device *dev = (struct net_device *)vif->vif_os;
    struct sk_buff *skb = vp_os_packet(pkt);
    struct skb_shared_info *sinfo;
    struct vr_ip *ip;
    struct vr_ip6 *ip6;
    int proto;
    unsigned short network_off, transport_off, cksum_off;

    skb->data = pkt_data(pkt);
    skb->len = pkt_len(pkt);
    skb_set_tail_pointer(skb, pkt_head_len(pkt));
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0))
    skb_sender_cpu_clear(skb);
#endif

    skb->dev = dev;
    if (!dev) {
        vif_drop_pkt(vif, pkt, false);
        return 0;
    }

    skb_reset_mac_header(skb);
    /* linux subtracts 1 from the queue value */
    if (pkt->vp_queue != VP_QUEUE_INVALID)
        skb->queue_mapping = pkt->vp_queue + 1;

    if (!vif_is_fabric(vif) ||
            (vr_priority_tagging || is_vlan_dev(dev))) {
        if (pkt->vp_priority != VP_PRIORITY_INVALID) {
            skb->priority = pkt->vp_priority;
        } else {
            skb->priority = TC_PRIO_BESTEFFORT;
        }
    } else {
        skb->priority = TC_PRIO_CONTROL;
    }

    /*
     * Set the network header and trasport header of skb only if the type is
     * IP (tunnel or non tunnel). This is required for those packets where
     * a new buffer is added at the head. Also, set it for packets from the
     * agent, which get sent to the NIC driver (to handle cases where the
     * NIC has hw vlan acceleration enabled).
     */
    if (pkt->vp_type == VP_TYPE_AGENT) {
        network_off = pkt_get_inner_network_header_off(pkt);
        if (network_off) {
            skb_set_network_header(skb, (network_off - skb_headroom(skb)));
            skb_reset_mac_len(skb);
        }
    } else if (vr_pkt_type_is_overlay(pkt->vp_type) ||
            vr_pkt_needs_csum_gso_update(pkt)) {
        network_off = pkt_get_inner_network_header_off(pkt);

        if (network_off) {
            ip = (struct vr_ip *)(pkt_data_at_offset(pkt, network_off));
            if (vr_ip_is_ip4(ip)) {
                transport_off = network_off + (ip->ip_hl * 4);
                proto = ip->ip_proto;
            } else if (vr_ip_is_ip6(ip)) {
                ip6 = (struct vr_ip6 *)ip;
                transport_off = network_off + sizeof(struct vr_ip6);
                proto = ip6->ip6_nxt;
                if (proto == VR_IP6_PROTO_FRAG) {
                    transport_off += sizeof(struct vr_ip6_frag);
                    proto = ((struct vr_ip6_frag *)(ip6 + 1))->ip6_frag_nxt;
                }
            } else {
                lh_pfree_skb(skb, vif, VP_DROP_INVALID_PROTOCOL);
                return 0;
            }

            skb_set_network_header(skb, (network_off - skb_headroom(skb)));
            skb_reset_mac_len(skb);
            skb_set_transport_header(skb, (transport_off - skb_headroom(skb)));

            /*
             * Manipulate partial checksum fields.
             * There are cases like mirroring where the UDP headers are newly added
             * and skb needs to be filled with proper offsets. The vr_packet's fields
             * are latest values and they need to be reflected in skb
             */
            if (pkt->vp_flags & VP_FLAG_CSUM_PARTIAL) {
                cksum_off = skb->csum_offset;
                if (proto == VR_IP_PROTO_TCP)
                    cksum_off = offsetof(struct vr_tcp, tcp_csum);
                else if (proto == VR_IP_PROTO_UDP)
                    cksum_off = offsetof(struct vr_udp, udp_csum);

                skb_partial_csum_set(skb, (transport_off - skb_headroom(skb)), cksum_off);
            }

            /*
             * Invoke segmentation only incase of both vr_packet and skb having gso
             */
            if ((pkt->vp_flags & VP_FLAG_GSO) && skb_is_gso(skb)) {
                /*
                 * it is possible that when we mirrored the packet, the inner
                 * packet was meant to be GSO-ed, and that would have been a
                 * TCP packet. Since we carried over the gso type from the inner
                 * packet, the value will be wrong, and that's where the following
                 * check comes into picture
                 */
                if (proto == VR_IP_PROTO_UDP) {
                    sinfo = skb_shinfo(skb);
                    if (!(sinfo->gso_type & SKB_GSO_UDP)) {
                        sinfo->gso_type &= ~(SKB_GSO_TCPV4 | SKB_GSO_TCP_ECN |
                            SKB_GSO_TCPV6 | SKB_GSO_FCOE);
                        sinfo->gso_type |= SKB_GSO_UDP;
                    }
                }

                if (vif->vif_type == VIF_TYPE_PHYSICAL) {
                    linux_gso_xmit(vif, skb, pkt->vp_type);
                    return 0;
                }
            }
        }
    } else {
        network_off = pkt_get_network_header_off(pkt);
        if (network_off) {
            skb_set_network_header(skb, (network_off - skb_headroom(skb)));
            skb_reset_mac_len(skb);
        }
    }

    linux_xmit_segment(vif, skb, pkt->vp_type,
            (pkt->vp_flags & VP_FLAG_DIAG));

    return 0;
}

inline struct vr_packet *
linux_get_packet(struct sk_buff *skb, struct vr_interface *vif)
{
    struct vr_packet *pkt;
    unsigned int length;

    pkt = (struct vr_packet *)skb->cb;
    pkt->vp_cpu = vr_get_cpu();
    pkt->vp_head = skb->head;

    length = skb_tail_pointer(skb) - skb->head;
    if (length >= (1 << (sizeof(pkt->vp_tail) * 8)))
        goto drop;
    pkt->vp_tail = length;

    length = skb->data - skb->head;
    if (length >= (1 << (sizeof(pkt->vp_data) * 8)))
        goto drop;
    pkt->vp_data = length;

    length = skb_end_pointer(skb) - skb->head;
    if (length >= (1 << (sizeof(pkt->vp_end) * 8)))
        goto drop;
    pkt->vp_end = length;

    pkt->vp_len = skb_headlen(skb);
    pkt->vp_if = vif;
    pkt->vp_network_h = pkt->vp_inner_network_h = 0;
    pkt->vp_nh = NULL;
    pkt->vp_flags = 0;
    if (skb->ip_summed == CHECKSUM_PARTIAL)
        pkt->vp_flags |= VP_FLAG_CSUM_PARTIAL;

    pkt->vp_ttl = 64;
    pkt->vp_type = VP_TYPE_NULL;
    pkt->vp_queue = VP_QUEUE_INVALID;
    pkt->vp_priority = VP_PRIORITY_INVALID;

    return pkt;

drop:
    vr_pfree(pkt, VP_DROP_INVALID_PACKET);
    return NULL;
}

int
linux_to_vr(struct vr_interface *vif, struct sk_buff *skb)
{
    struct vr_packet *pkt;

    if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
        return 0;

    pkt = linux_get_packet(skb, vif);
    if (!pkt)
        return 0;

    vif->vif_rx(vif, pkt, VLAN_ID_INVALID);

    return 0;
}

static int
linux_pull_outer_headers(struct sk_buff *skb)
{
    struct vlan_hdr *vhdr;
    bool thdr = false, pull = false;
    uint16_t proto, offset, ip_proto = 0, ip_hdr_len = 0;
    struct iphdr *iph = NULL;
    struct ipv6hdr *ip6h = NULL;
    struct vr_icmp *icmph;
    struct vr_ip6_frag *v6_frag;

    offset = skb->mac_len;
    proto = skb->protocol;

    while (proto == htons(ETH_P_8021Q)) {
        offset += sizeof(struct vlan_hdr);
        if (!pskb_may_pull(skb, offset))
            goto pull_fail;
        vhdr = (struct vlan_hdr *)(skb->data + offset);
        proto = vhdr->h_vlan_encapsulated_proto;
    }

    if (likely(proto == htons(ETH_P_IP))) {
        skb_set_network_header(skb, offset);

        offset += sizeof(struct iphdr);
        if (!pskb_may_pull(skb, offset))
            goto pull_fail;

        iph = ip_hdr(skb);
        ip_hdr_len = iph->ihl * 4;
        offset += (iph->ihl * 4) - sizeof(struct iphdr);
        if (!pskb_may_pull(skb, offset))
            goto pull_fail;
        iph = ip_hdr(skb);
        thdr = vr_ip_transport_header_valid((struct vr_ip *)iph);
        pull = vr_ip_proto_pull((struct vr_ip *)iph);
        if (pull && thdr) {
            ip_proto = iph->protocol;
        }
    } else if (proto == htons(ETH_P_IPV6)) {
        skb_set_network_header(skb, offset);

        offset += sizeof(struct ipv6hdr);
        if (!pskb_may_pull(skb, offset))
            goto pull_fail;

        ip_hdr_len = sizeof(struct ipv6hdr);
        ip6h = ipv6_hdr(skb);
        pull = vr_ip6_proto_pull((struct vr_ip6 *)ip6h);
        if (pull) {
            ip_proto = ip6h->nexthdr;
            if (ip_proto == VR_IP6_PROTO_FRAG) {
                offset += sizeof(struct vr_ip6_frag);
                if (!pskb_may_pull(skb, offset))
                    goto pull_fail;
                ip_hdr_len += sizeof(struct vr_ip6_frag);
                ip6h = ipv6_hdr(skb);
                thdr = vr_ip6_transport_header_valid((struct vr_ip6 *)ip6h);
                v6_frag = (struct vr_ip6_frag *)(ip6h + 1);
                ip_proto = v6_frag->ip6_frag_nxt;
            }
        }
    } else if (proto == htons(ETH_P_ARP)) {
        offset += sizeof(struct vr_arp);
        if (!pskb_may_pull(skb, offset))
            goto pull_fail;
    }

    if (thdr && pull && (iph || ip6h)) {
        if (ip_proto == VR_IP_PROTO_TCP) {
            offset += sizeof(struct vr_tcp);
            if (!pskb_may_pull(skb, offset))
                goto pull_fail;
        } else {
            /*
             * this covers both regular port number offsets that come in
             * the first 4 bytes and the icmp header
             */
            offset += sizeof(struct vr_icmp);
            if (!pskb_may_pull(skb, offset))
                goto pull_fail;
        }

        if (iph)
            iph = ip_hdr(skb);
        else
            ip6h = ipv6_hdr(skb);

        if (ip_proto == VR_IP_PROTO_ICMP) {
            if (vr_icmp_error((struct vr_icmp *)((unsigned char *)iph +
                            ip_hdr_len))) {
                iph = (struct iphdr *)(skb->data + offset);
                offset += sizeof(struct iphdr);
                if (!pskb_may_pull(skb, offset))
                    goto pull_fail;

                iph = (struct iphdr *)(skb->data + offset - sizeof(struct iphdr));
                if (vr_ip_proto_pull((struct vr_ip *)iph)) {
                    offset += (iph->ihl * 4) - sizeof(struct iphdr) +
                        sizeof(struct vr_icmp);

                    if (!pskb_may_pull(skb, offset))
                        goto pull_fail;
                }
            }
        } else if (ip_proto == VR_IP_PROTO_ICMP6) {
            icmph = (struct vr_icmp *) ((char *)ip6h + ip_hdr_len);
            if (icmph->icmp_type == VR_ICMP6_TYPE_NEIGH_SOL) {
                /*
                 * ICMPV6 header contain Target address which is mandatory
                 * and is 16 byte long. Possibly it can only contain an option
                 * which is MAC address length long
                 */
                offset += VR_IP6_ADDRESS_LEN;
                if (skb->len >= (offset + sizeof(struct vr_neighbor_option) +
                                          VR_ETHER_ALEN)) {
                    offset += VR_ETHER_ALEN +
                              sizeof(struct vr_neighbor_option);
                }

                if (!pskb_may_pull(skb, offset))
                    goto pull_fail;
            } else if (vr_icmp6_error(icmph)) {
                offset += sizeof(struct ipv6hdr);
                if (!pskb_may_pull(skb, offset))
                    goto pull_fail;
                ip6h = (struct ipv6hdr *)(skb->data + offset -
                        sizeof(struct ipv6hdr));
                if (ip6h->nexthdr == VR_IP6_PROTO_FRAG) {
                    offset += sizeof(struct vr_ip6_frag) +
                                    sizeof(struct vr_icmp);
                    if (!pskb_may_pull(skb, offset))
                        goto pull_fail;

                    return 0;
                }

                if (vr_ip6_proto_pull((struct vr_ip6 *)ip6h)) {
                    offset += sizeof(struct vr_icmp);
                    if (!pskb_may_pull(skb, offset))
                        goto pull_fail;
                }
            }
        }
    }

    return 0;

pull_fail:
    return -1;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
rx_handler_result_t
linux_rx_handler(struct sk_buff **pskb)
{
    int ret;
    unsigned short vlan_id = VLAN_ID_INVALID;
    struct sk_buff *skb = *pskb;
    struct vr_packet *pkt;
    struct net_device *dev = skb->dev;
    struct vr_interface *vif;
    unsigned int curr_cpu;
    u16 rxq;
    int rpsdev = 0;
    struct vrouter *router;

    /*
     * If we did RPS immediately after the packet was received from the
     * physical interface (vr_perfr3 is set), we are now running on a
     * new core. Extract the vif information that was saved in the skb
     * on the previous core.
     */
    if (skb->dev == pkt_rps_dev) {
        router = vrouter_get(((vr_rps_t *)skb->cb)->vif_rid);
        if (router == NULL) {
            goto error;
        }
            
        vif = __vrouter_get_interface(router,
                  ((vr_rps_t *)skb->cb)->vif_idx);
        if (vif && (vif->vif_type == VIF_TYPE_PHYSICAL) && vif->vif_os) {
            dev = (struct net_device *)vif->vif_os;
            if (!dev || (vif != rcu_dereference(dev->rx_handler_data)))
                goto error;
            rpsdev = 1;
        } else {
            goto error;
        }
    }

    vif = rcu_dereference(dev->rx_handler_data);

    if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
        return RX_HANDLER_PASS;

#ifdef CONFIG_RPS
    /*
     * Send the packet to another CPU core if vr_perfr3 is set. The new
     * CPU core is chosen based on a hash of the outer header. This only needs
     * to be done for packets arriving on a physical interface. Also, we
     * only need to do this if RPS hasn't already happened.
     */
    if (vr_perfr3 && (!rpsdev) && (vif->vif_type == VIF_TYPE_PHYSICAL)) {
        curr_cpu = vr_get_cpu();
        if (vr_perfq3) {
            rxq = vr_perfq3;
        } else {
            linux_get_rxq(skb, &rxq, curr_cpu, 0);
        }

        skb_record_rx_queue(skb, rxq);
        vr_skb_set_rxhash(skb, curr_cpu);
        skb->dev = pkt_rps_dev;

        /*
         * Store vif information in skb for later retrieval
         */
        ((vr_rps_t *)skb->cb)->vif_idx = vif->vif_idx;
        ((vr_rps_t *)skb->cb)->vif_rid = vif->vif_rid;

        netif_receive_skb(skb);
        return RX_HANDLER_CONSUMED;
    }
#endif

    if (dev->type == ARPHRD_ETHER) {
        skb_push(skb, skb->mac_len);
        if (skb->vlan_tci & VLAN_TAG_PRESENT) {
            if (!(skb = linux_skb_vlan_insert(vif, skb,
                            skb->vlan_tci & 0xEFFF)))
                return RX_HANDLER_CONSUMED;

            vlan_id = skb->vlan_tci & 0xFFF;
            skb->vlan_tci = 0;
        }
    } else {
        if (skb_headroom(skb) < ETH_HLEN) {
            ret = pskb_expand_head(skb, ETH_HLEN - skb_headroom(skb) +
                    ETH_HLEN + sizeof(struct agent_hdr), 0, GFP_ATOMIC);
            if (ret)
                goto error;
        }
    }

    ret = linux_pull_outer_headers(skb);
    if (ret < 0)
        goto error;


    pkt = linux_get_packet(skb, vif);
    if (!pkt)
        return RX_HANDLER_CONSUMED;

    if (vif->vif_type == VIF_TYPE_PHYSICAL) {
        if ((!(vif->vif_flags & VIF_FLAG_PROMISCOUS)) &&
                (skb->pkt_type == PACKET_OTHERHOST)) {
            vif_drop_pkt(vif, pkt, true);
            return RX_HANDLER_CONSUMED;
        }
    }

    ret = vif->vif_rx(vif, pkt, vlan_id);
    if (!ret)
        ret = RX_HANDLER_CONSUMED;

    return ret;

error:

     pkt = (struct vr_packet *)skb->cb;
     vr_pfree(pkt, VP_DROP_MISC);

     return RX_HANDLER_CONSUMED;

}
#else

#ifdef CONFIG_RPS
/*
 * vr_do_rps_outer - perform RPS based on the outer header immediately after
 * the packet is received from the physical interface.
 */
static void
vr_do_rps_outer(struct sk_buff *skb, struct vr_interface *vif)
{
    unsigned int curr_cpu;
    u16 rxq;

    curr_cpu = vr_get_cpu();
    if (vr_perfq3) {
        rxq = vr_perfq3;
    } else {
        linux_get_rxq(skb, &rxq, curr_cpu, 0);
    }

    skb_record_rx_queue(skb, rxq);
    vr_skb_set_rxhash(skb, curr_cpu);
    skb->dev = pkt_rps_dev;

    /*
     * Store vif information in skb for later retrieval
     */
    ((vr_rps_t *)skb->cb)->vif_idx = vif->vif_idx;
    ((vr_rps_t *)skb->cb)->vif_rid = vif->vif_rid;

    netif_receive_skb(skb);

    return;
}

/*
 * vr_get_vif_ptr - gets a pointer to the vif structure from the netdevice
 * structure depending on whether vrouter uses the bridge or OVS hook.
 */
static struct vr_interface *
vr_get_vif_ptr(struct net_device *dev)
{
    struct vr_interface *vif;

    if (vr_use_linux_br) {
        vif = (struct vr_interface *) rcu_dereference(dev->br_port);
    } else {
        vif = (struct vr_interface *) rcu_dereference(dev->ax25_ptr);
    }

    return vif;
}

/*
 * vr_set_vif_ptr - sets a pointer to the vif structure in the netdevice
 * structure depending on whether vrouter uses the bridge or OVS hook.
 */
void
vr_set_vif_ptr(struct net_device *dev, void *vif)
{
    if (vr_use_linux_br) {
        rcu_assign_pointer(dev->br_port, vif);
    } else {
        rcu_assign_pointer(dev->ax25_ptr, vif);
        if (vif) {
            dev->priv_flags |= IFF_OVS_DATAPATH;
        } else {
            dev->priv_flags &= (~IFF_OVS_DATAPATH);
        }
    }

    return;
}
#endif

/*
 * vr_post_rps_get_phys_dev - get the physical interface that the packet
 * arrived on, after RPS is performed based on the outer header. Returns
 * the interface pointer on success, NULL otherwise.
 */
static struct net_device *
vr_post_rps_outer_get_phys_dev(struct sk_buff *skb)
{
    struct net_device *dev = NULL;
    struct vrouter *router;
    struct vr_interface *vif;

    router = vrouter_get(((vr_rps_t *)skb->cb)->vif_rid);
    if (router == NULL) {
        return NULL;
    }

    vif = __vrouter_get_interface(router,
              ((vr_rps_t *)skb->cb)->vif_idx);
    if (vif && (vif->vif_type == VIF_TYPE_PHYSICAL) && vif->vif_os) {
        dev = (struct net_device *) vif->vif_os;
    }

    return dev;
}

/*
 * vr_interface_common_hook
 *
 * Common function called by both bridge and OVS hooks in 2.6 kernels.
 */
static struct sk_buff *
vr_interface_common_hook(struct sk_buff *skb)
{
    unsigned short vlan_id = VLAN_ID_INVALID;
    struct vr_interface *vif;
    struct vr_packet *pkt;
    struct vlan_hdr *vhdr;
    int rpsdev = 0;
    int ret;
    struct net_device *dev, *vdev;

    /*
     * LACP packets should go to the protocol handler. Hence do not
     * claim those packets. This action is not needed in 3.x kernels
     * because packets are claimed by the protocol handler from the
     * component interface itself by means of netdev_rx_handler
     */
    if (skb->protocol == __be16_to_cpu(ETH_P_SLOW))
        return skb;

    if (skb->dev == NULL) {
        goto error;
    }
    dev = skb->dev;

    if (vr_get_vif_ptr(skb->dev) == (&vr_reset_interface)) {
        vdev = vhost_get_vhost_for_phys(skb->dev);
        if (!vdev)
            goto error;
        skb->dev = vdev;
        (void)__sync_fetch_and_add(&vdev->stats.rx_bytes, skb->len);
        (void)__sync_fetch_and_add(&vdev->stats.rx_packets, 1);

        return skb;
    }


    if ((skb->dev == pkt_gro_dev) || (skb->dev == pkt_l2_gro_dev)) {
        pkt_gro_dev_rx_handler(&skb);
        return NULL;
    } else if (skb->dev == pkt_rps_dev) {
        if (!vr_perfr3) {
            pkt_rps_dev_rx_handler(&skb);
            return NULL;
        }

        dev = vr_post_rps_outer_get_phys_dev(skb);
        if (dev == NULL) {
            goto error;
        }

        rpsdev = 1;
        vif = vr_get_vif_ptr(dev);
    } else {
        vif = vr_get_vif_ptr(skb->dev);
    }

    if (!vif)
        goto error;

#if 0
    if(vrouter_dbg) {
        __skb_dump_info("vr_intf_br_hk:", skb, vif);
    }
#endif

    if ((skb = skb_share_check(skb, GFP_ATOMIC)) == NULL)
        return skb;

#ifdef CONFIG_RPS
    /*
     * Send the packet to another CPU core if vr_perfr3 is set. The new
     * CPU core is chosen based on a hash of the outer header. This only needs
     * to be done for packets arriving on a physical interface. Also, we
     * only need to do this if RPS hasn't already happened.
     */
    if (vr_perfr3 && (!rpsdev) && (vif->vif_type == VIF_TYPE_PHYSICAL)) {
        vr_do_rps_outer(skb, vif);
        
        return NULL;
    }
#endif

    if (skb->protocol == htons(ETH_P_8021Q)) {
        vhdr = (struct vlan_hdr *)skb->data;
        vlan_id = ntohs(vhdr->h_vlan_TCI) & VLAN_VID_MASK;
    }

    if (dev->type == ARPHRD_ETHER) {
        skb_push(skb, skb->mac_len);
    } else {
        if (skb_headroom(skb) < ETH_HLEN) {
            ret = pskb_expand_head(skb, ETH_HLEN - skb_headroom(skb) +
                    ETH_HLEN + sizeof(struct agent_hdr), 0, GFP_ATOMIC);
            if (ret)
                goto error;
        }
    }

    ret = linux_pull_outer_headers(skb);
    if (ret < 0)
        goto error;

    pkt = linux_get_packet(skb, vif);
    if (!pkt)
        return NULL;

    if (vif->vif_type == VIF_TYPE_PHYSICAL) {
        if ((!(vif->vif_flags & VIF_FLAG_PROMISCOUS)) &&
                (skb->pkt_type == PACKET_OTHERHOST)) {
            vif_drop_pkt(vif, pkt, true);
            return RX_HANDLER_CONSUMED;
        }
    }

    vif->vif_rx(vif, pkt, vlan_id);
    return NULL;

error:

    pkt = (struct vr_packet *)skb->cb;
    vr_pfree(pkt, VP_DROP_MISC);

    return NULL;
}

/*
 * vr_interface_bridge_hook
 *
 * Intercept packets received on virtual interfaces in kernel versions that
 * do not support the netdev_rx_handler_register API. This makes the vrouter
 * module incompatible with the bridge module.
 */
static struct sk_buff *
vr_interface_bridge_hook(struct net_bridge_port *port, struct sk_buff *skb)
{
    return vr_interface_common_hook(skb);
}

/*
 * vr_interface_ovs_hook
 *
 * Intercept packets received on virtual interfaces in kernel versions that
 * do not support the netdev_rx_handler_register API. This makes the vrouter
 * module incompatible with the openvswitch module.
 */
static struct sk_buff *
vr_interface_ovs_hook(struct sk_buff *skb)
{
    return vr_interface_common_hook(skb);
}

#endif
/*
 * both add tap and del tap can come from multiple contexts. one is
 * obviously when interface is deleted from vrouter on explicit request
 * from agent. other is when the physical interface underlying the
 * vrouter interface dies, in which case we will be notified and
 * have to take corrective actions. hence, it is vital that we check
 * whether 'rtnl' was indeed locked before trying to acquire the lock
 * and unlock iff we locked it in the first place.
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36))
static int
linux_if_del_tap(struct vr_interface *vif)
{
    struct net_device *dev;

    if (vif->vif_type == VIF_TYPE_STATS)
        return 0;

    dev = (struct net_device *)vif->vif_os;
    if (!dev)
        return -EINVAL;

    if (rcu_dereference(dev->rx_handler) == linux_rx_handler)
        netdev_rx_handler_unregister(dev);

    return 0;
}
#else
static int
linux_if_del_tap(struct vr_interface *vif)
{
    struct net_device *dev;

    if (vif->vif_type == VIF_TYPE_STATS)
        return 0;

    dev = (struct net_device *)vif->vif_os;
    if (!dev)
        return -EINVAL;

    if (vr_get_vif_ptr(dev) == (void *)vif) {
        if ((vif->vif_type == VIF_TYPE_PHYSICAL) &&
                (vif->vif_flags & VIF_FLAG_VHOST_PHYS)) {
            vr_set_vif_ptr(dev, &vr_reset_interface);
        } else {
            vr_set_vif_ptr(dev, NULL);
        }
    }

    return 0;
}
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
static int
linux_if_add_tap(struct vr_interface *vif)
{
    struct net_device *dev;

    if (vif->vif_type == VIF_TYPE_STATS)
        return 0;

    if (vif->vif_name[0] == '\0')
        return -ENODEV;

    dev = (struct net_device *)vif->vif_os;
    if (!dev)
        return -EINVAL;

    if ((vif->vif_type == VIF_TYPE_PHYSICAL) &&
            (vif->vif_flags & VIF_FLAG_VHOST_PHYS)) {
        if (rcu_dereference(dev->rx_handler) == vhost_rx_handler) {
            netdev_rx_handler_unregister(dev);
        }
    }

    return netdev_rx_handler_register(dev, linux_rx_handler, (void *)vif);
}
#else
static int
linux_if_add_tap(struct vr_interface *vif)
{
    struct net_device *dev;

    if (vif->vif_type == VIF_TYPE_STATS)
        return 0;

    if (vif->vif_name[0] == '\0')
        return -ENODEV;

    dev = (struct net_device *)vif->vif_os;
    if (!dev)
        return -EINVAL;

    vr_set_vif_ptr(dev, (void *)vif);

    return 0;
}
#endif

static int
linux_if_get_settings(struct vr_interface *vif,
        struct vr_interface_settings *settings)
{
    struct net_device *dev = (struct net_device *)vif->vif_os;
    int ret = -EINVAL;

    if (vif->vif_type != VIF_TYPE_PHYSICAL || !dev)
        return ret;

    rtnl_lock();

    if (netif_running(dev)) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,0))
        /* ethtool_link_ksettings introduced since kernel 4.6. ethtool_cmd has been removed */
        struct ethtool_link_ksettings ekmd;
        ekmd.base.cmd = ETHTOOL_GSET;
        if  (!(ret = __ethtool_get_link_ksettings(dev, &ekmd))) {
            settings->vis_speed = ekmd.base.speed;
            settings->vis_duplex = ekmd.base.duplex;
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0) && LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0))
        struct ethtool_cmd cmd;
        /* As per lxr, this API was introduced in 3.2.0 */
        if (!(ret = __ethtool_get_settings(dev, &cmd))) {
            settings->vis_speed = ethtool_cmd_speed(&cmd);
            settings->vis_duplex = cmd.duplex;
#endif
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0))
        struct ethtool_cmd cmd;
        cmd.cmd = ETHTOOL_GSET;
        if  (!(ret = dev_ethtool_get_settings(dev, &cmd))) {
            settings->vis_speed = cmd.speed;
            settings->vis_duplex = cmd.duplex;
#endif

        }
    }

    rtnl_unlock();

    return ret;
}

static unsigned int
linux_if_get_mtu(struct vr_interface *vif)
{
    struct net_device *dev = (struct net_device *)vif->vif_os;

    if (dev)
        return dev->mtu;
    else
        return vif->vif_mtu;
}

static unsigned short
linux_if_get_encap(struct vr_interface *vif)
{
    struct net_device *dev = (struct net_device *)vif->vif_os;

    if (dev && (dev->type != ARPHRD_ETHER))
        return VIF_ENCAP_TYPE_L3;

    return VIF_ENCAP_TYPE_ETHER;
}

/*
 * linux_if_tx_csum_offload - returns 1 if the device supports checksum offload
 * on transmit for tunneled packets. Devices which have NETIF_F_HW_CSUM set
 * are capable of doing this, but there are some devices (such as ixgbe, i40e)
 * which support it even though they don't set NETIF_F_HW_CSUM.
 */
static int
linux_if_tx_csum_offload(struct net_device *dev)
{
    const char *driver_name;

    if (dev->features & NETIF_F_HW_CSUM) {
        return 1;
    }

#ifndef RHEL_MAJOR
    if (dev->dev.parent) {
        driver_name = dev_driver_string(dev->dev.parent);
        if (driver_name && ((!strncmp(driver_name, "ixgbe", 6)) ||
                            (!strncmp(driver_name, "i40e", 5)))) {
            return 1;
        }
    }
#endif

    return 0;
}

static int
linux_if_del(struct vr_interface *vif)
{
    if (vif_needs_dev(vif) && !vif->vif_os_idx)
        return 0;

    if (vif_is_vhost(vif))
        vhost_if_del((struct net_device *)vif->vif_os);
    else if (vif->vif_type == VIF_TYPE_PHYSICAL)
        vhost_if_del_phys((struct net_device *)vif->vif_os);
    else if (vif_is_virtual(vif)) {
        /*
         * if the napi structure was not initialised in the first place, we
         * should not touch it now, since doing a netif_napi_del results in a
         * crash. however, there are no reliable checks. hence, for now we
         * will check for poll. ideally, we should not have had the napi
         * structure itself in the interface structure and that would have
         * clearly told us what to do with napi
         */
        if (vif->vr_napi.poll) {
            napi_disable(&vif->vr_napi);
            netif_napi_del(&vif->vr_napi);
        }
        skb_queue_purge(&vif->vr_skb_inputq);
        if (vif->vr_l2_napi.poll) {
            napi_disable(&vif->vr_l2_napi);
            netif_napi_del(&vif->vr_l2_napi);
        }
        skb_queue_purge(&vif->vr_skb_l2_inputq);
    }

    if (vif->vif_os) {
        if (vif->vif_type == VIF_TYPE_STATS)
            ((struct net_device *)vif->vif_os)->ml_priv = NULL;
        dev_put((struct net_device *)vif->vif_os);
    }

    vif->vif_os = NULL;
    vif->vif_os_idx = 0;

    return 0;
}

static int
linux_if_add(struct vr_interface *vif)
{
    struct net_device *dev;

    if (vif_needs_dev(vif)) {
        if (!vif->vif_os_idx || vif->vif_name[0] == '\0') {
            return -ENODEV;
        }
    }

    if (vif->vif_os_idx) {
        dev = dev_get_by_index(&init_net, vif->vif_os_idx);
        if (!dev) {
            return -ENODEV;
        }

        vif->vif_os = (void *)dev;
        if (vif->vif_type == VIF_TYPE_PHYSICAL) {
            if (linux_if_tx_csum_offload(dev)) {
                vif->vif_flags |= VIF_FLAG_TX_CSUM_OFFLOAD;
            }
        }

        if (vif->vif_type == VIF_TYPE_STATS)
            dev->ml_priv = (void *)vif;
    }

    if (vif_is_vhost(vif))
        vhost_if_add(vif);

    if (vif_is_virtual(vif)) {
        skb_queue_head_init(&vif->vr_skb_inputq);
        netif_napi_add(pkt_gro_dev, &vif->vr_napi, vr_napi_poll, 64);
        napi_enable(&vif->vr_napi);

        /* Lets enable for L2 as well */
        skb_queue_head_init(&vif->vr_skb_l2_inputq);
        netif_napi_add(pkt_l2_gro_dev, &vif->vr_l2_napi, vr_napi_poll, 64);
        napi_enable(&vif->vr_l2_napi);
    }

    return 0;
}

static void
linux_if_unlock(void)
{
    rtnl_unlock();
    return;
}

static void
linux_if_lock(void)
{
    rtnl_lock();
    return;
}

/*
 * linux_pkt_dev_free_helper - free the packet device
 */
static void
linux_pkt_dev_free_helper(struct net_device **dev)
{
    if (*dev == NULL) {
        return;
    }

    unregister_netdev(*dev);
    free_netdev(*dev);
    *dev = NULL;

    return;
}

/*
 * linux_pkt_dev_free - free the packet device used for GRO/RPS
 */
static void
linux_pkt_dev_free(void)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39))
    if (pkt_gro_dev) {
        vr_set_vif_ptr(pkt_gro_dev, NULL);
    }
    if (pkt_l2_gro_dev) {
        vr_set_vif_ptr(pkt_l2_gro_dev, NULL);
    }
#endif
    linux_pkt_dev_free_helper(&pkt_gro_dev);
    linux_pkt_dev_free_helper(&pkt_l2_gro_dev);
    linux_pkt_dev_free_helper(&pkt_rps_dev);
 
    return;
}


/*
 * pkt_gro_dev_setup - fill in the relevant fields of the GRO packet device
 */
static void
pkt_gro_dev_setup(struct net_device *dev)
{
    /*
     * Initializing the interfaces with basic parameters to setup address
     * families.
     */
    random_ether_addr(dev->dev_addr);
    dev->addr_len = ETH_ALEN;

    /*
     * The hard header length is used by the GRO code to compare the
     * MAC header of the incoming packet with the MAC header of packets
     * undergoing GRO at the moment. In our case, each VM wil have
     * unique nexthop id  associated with it, so we can use nexthop id
     * as the MAC header to combine packets destined for the same vif.
     * In addition to nh id, we need to keep the context of receiving
     * inteface, post gro, for packet processing. So vif id inaddition
     * to nh id is used as L2 header
     */

    dev->hard_header_len = 2 * sizeof(unsigned short);

    dev->type = ARPHRD_VOID;
    dev->netdev_ops = &pkt_gro_dev_ops;
    dev->features |= NETIF_F_GRO;
    dev->mtu = 65535;

    return;
}

static void
pkt_l2_gro_dev_setup(struct net_device *dev)
{
    pkt_gro_dev_setup(dev);
    dev->hard_header_len = 2 * sizeof(unsigned short) + VR_ETHER_HLEN;
    return;
}


/*
 * pkt_rps_dev_setup - fill in the relevant fields of the RPS packet device
 */
static void
pkt_rps_dev_setup(struct net_device *dev)
{
    /*
     * Initializing the interfaces with basic parameters to setup address
     * families.
     */
    random_ether_addr(dev->dev_addr);
    dev->addr_len = ETH_ALEN;

    dev->hard_header_len = ETH_HLEN;

    dev->type = ARPHRD_VOID;
    dev->netdev_ops = &pkt_rps_dev_ops;
    dev->mtu = 65535;

    return;
}

/*
 * linux_pkt_dev_init - initialize the packet device used for GRO. Returns 
 * pointer to packet device if no errors, NULL otherwise.
 */
static struct net_device *
linux_pkt_dev_init(char *name, void (*setup)(struct net_device *),
                   rx_handler_result_t (*handler)(struct sk_buff **))
{
    int err = 0;
    struct net_device *pdev = NULL;

    pdev = alloc_netdev_mqs(0, name,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0))
#else
                            NET_NAME_UNKNOWN,
#endif
                            setup, 1, num_present_cpus());


    if (pdev == NULL) {
        vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, 0);
        return NULL;
    }

    rtnl_lock();

    if ((err = register_netdevice(pdev))) {
        vr_module_error(err, __FUNCTION__, __LINE__, 0);
    } else {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39))
        if ((err = netdev_rx_handler_register(pdev,
                                              handler, NULL))) {
            vr_module_error(err, __FUNCTION__, __LINE__, 0);
            unregister_netdev(pdev);
        }
#else
        vr_set_vif_ptr(pdev, (void *) pdev);
#endif
    }

    rtnl_unlock();

    if (err) {
        free_netdev(pdev);
        return NULL;
    }

    return pdev;
}

#ifdef CONFIG_RPS
int
lh_rps_process(struct vr_packet *pkt)
{
    u16 rxq;
    unsigned int curr_cpu = 0;
    struct sk_buff *skb = vp_os_packet(pkt);
    __u32 prev_cpu;

    /*
     * vr_perfr1 only takes effect if vr_perfr3 is not set. Also, if we are
     * coming here after RPS (skb->dev is pkt_rps_dev), vr_perfr1 is a no-op
     */
    if (vr_perfr1 && (!vr_perfr3) && (skb->dev != pkt_rps_dev)) {
        curr_cpu = vr_get_cpu();
        if (vr_perfq1) {
            rxq = vr_perfq1;
        } else {
            linux_get_rxq(skb, &rxq, curr_cpu, 0);
        }

        skb_record_rx_queue(skb, rxq);
        /*
         * Store current CPU in rxhash of skb
         */
        vr_skb_set_rxhash(skb, curr_cpu);
        skb->dev = pkt_rps_dev;

        /*
         * Clear the vr_rps_t vif_idx field in the skb->cb. This is to handle
         * the corner case of vr_perfr3 being enabled after a packet has
         * been scheduled for RPS with vr_perfr1 set, but before the
         * earlier RPS has completed. After RPS completes, linux_rx_handler()
         * will drop the packet as vif_idx is 0 (which corresponds to pkt0).
         */
        ((vr_rps_t *)skb->cb)->vif_idx = 0;

        netif_receive_skb(skb);

        return 0;
    }

    if (vr_perfr2) {
        if (vr_perfq2) {
            rxq = vr_perfq2;
        } else {
            /*
             * If RPS happened earlier (perfr1 or perfr3 is set),
             * prev_cpu was already been set in skb->rxhash.
             */
            prev_cpu = vr_skb_get_rxhash(skb);
            vr_skb_set_rxhash(skb, 0);
            linux_get_rxq(skb, &rxq, vr_get_cpu(),
                          (vr_perfr1 || vr_perfr3) ?  prev_cpu+1 : 0);
        }

        skb_record_rx_queue(skb, rxq);
    } else {
        skb_set_queue_mapping(skb, 0);
    }
    return 0;
}
#endif


int
lh_gro_process(struct vr_packet *pkt, struct vr_interface *vif, bool l2_pkt)
{
    int handled = 1;

    struct sk_buff *skb = vp_os_packet(pkt);
#ifdef XEN_HYPERVISOR
    unsigned char *data;
    if (l2_pkt)
        return !handled;
#endif

    if (skb_cloned(skb))
        return !handled;

    skb->data = pkt_data(pkt);
    skb->len = pkt_len(pkt);
    skb_set_tail_pointer(skb, pkt_head_len(pkt));

#ifdef XEN_HYPERVISOR
    /*
     * The nexthop id has been added as L2 header here. For Xen,
     * Ethernet header is the L2 header for GRO
     */
    if (unlikely(skb_headroom(skb) < (ETH_HLEN - sizeof(unsigned short)))) {
        struct sk_buff *nskb = skb_realloc_headroom(skb,
                LL_RESERVED_SPACE(skb->dev));
        if (!nskb) {
            vif_drop_pkt(vif, pkt, false);
            if (net_ratelimit())
                printk(KERN_WARNING
                     "Insufficient memory: %s %d\n",
                    __FUNCTION__, __LINE__);
            return handled;
        }
        memcpy(nskb->data, skb->data , sizeof(unsigned short));
        kfree_skb(skb);
        skb = nskb;
    }
    data = skb_push(skb, ETH_HLEN - sizeof(unsigned short));
    memset(data, 0xFE, ETH_HLEN - sizeof(unsigned short));

#endif
    skb_reset_mac_header(skb);

    if (!skb_pull(skb, pkt->vp_network_h - (skb->data - skb->head))) {
        vr_pfree(pkt, VP_DROP_PULL);
        return handled;
    }

    skb_reset_network_header(skb);
#ifdef CONFIG_RPS
    lh_rps_process(pkt);
#endif
    linux_enqueue_pkt_for_gro(skb, vif, l2_pkt);
    return handled;
}

static rx_handler_result_t 
pkt_gro_dev_rx_handler(struct sk_buff **pskb)
{
    unsigned short nh_id, vif_id, drop_reason;

    struct vrouter *router = vrouter_get(0);
    struct vr_gro *gro;
    struct vr_nexthop *nh;
    struct vr_interface *vif, *gro_vif;
    struct vr_interface_stats *gro_vif_stats;
    struct vr_packet *pkt = NULL;
    struct vr_forwarding_md fmd;
    struct sk_buff *skb = *pskb;

#ifdef XEN_HYPERVISOR
    unsigned char *data;

    data = skb_mac_header(skb);
    nh_id = *((unsigned short *)(data + (ETH_HLEN - sizeof(unsigned short))));
    if (!skb_push(skb, VR_ETHER_HLEN)) {
        drop_reason = VP_DROP_INVALID_PACKET;
        goto drop;
    }
#else
    gro = (struct vr_gro *)skb_mac_header(skb);
    vif_id = gro->vg_vif_id;
    nh_id = gro->vg_nh_id;
#endif

    gro_vif = skb->dev->ml_priv;

    nh = __vrouter_get_nexthop(router, nh_id);
    if (!nh) {
        drop_reason = VP_DROP_INVALID_NH;
        goto drop;
    }
    vif = nh->nh_dev;
    if ((vif == NULL) || (!vif_is_virtual(vif))) {
        drop_reason = VP_DROP_INVALID_IF;
        goto drop;
    }

    if (nh->nh_family == AF_BRIDGE) {
        if (!skb_push(skb, VR_ETHER_HLEN)) {
            drop_reason = VP_DROP_INVALID_PACKET;
            goto drop;
        }
    }

    pkt = linux_get_packet(skb, NULL);
    if (!pkt)
        return RX_HANDLER_CONSUMED;

    pkt->vp_flags |= VP_FLAG_GROED;

    /*
     * since vif was not available when we did linux_get_packet, set vif
     * manually here
     */
    vif = __vrouter_get_interface(router, vif_id);
    if (!vif) {
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


    if (gro_vif) {
        gro_vif_stats = vif_get_stats(gro_vif, pkt->vp_cpu);
        if (gro_vif_stats) {
            gro_vif_stats->vis_ipackets++;
            gro_vif_stats->vis_ibytes += skb->len;
        }
    }

    pkt->vp_flags |= VP_FLAG_FLOW_SET;
    nh_output(pkt, nh, &fmd);
    return RX_HANDLER_CONSUMED;

drop:
    lh_pfree_skb(skb, gro_vif, drop_reason);
    return RX_HANDLER_CONSUMED;
}

/*
 * pkt_rps_dev_rx_handler - receive a packet after RPS
 */
static rx_handler_result_t
pkt_rps_dev_rx_handler(struct sk_buff **pskb)
{
    struct sk_buff *skb = *pskb;
    struct vr_packet *pkt;
    unsigned short nh_id;
    struct vr_nexthop *nh;
    struct vr_interface *vif;
    struct vrouter *router = vrouter_get(0);  
    bool l2_pkt = true;

    if (vr_perfr3) {
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
        ASSERT(0);
#else
        return linux_rx_handler(&skb);
#endif
    }

    pkt = (struct vr_packet *)skb->cb;

    /*
     * If RPS was scheduled earlier because of vr_perfr1 being set, the
     * vif_idx in skb->cb should be 0. If it is non-zero, RPS was scheduled
     * because of vr_perfr3 being set earlier (and now vr_perfr3 has been
     * cleared). Drop the packet in this corner case.
     */
    if (((vr_rps_t *)skb->cb)->vif_idx) {
        vr_pfree(pkt, VP_DROP_MISC);

        return RX_HANDLER_CONSUMED;
    }

#ifdef CONFIG_RPS
    lh_rps_process(pkt);
#endif

    nh_id = *((unsigned short *) skb_mac_header(skb));

    nh = __vrouter_get_nexthop(router, nh_id);
    if (!nh) {
        vr_pfree(pkt, VP_DROP_INVALID_NH);
        return RX_HANDLER_CONSUMED;
    }
    if (nh->nh_family == AF_INET)
        l2_pkt = false;

    vif = nh->nh_dev;
    if ((vif == NULL) || (!vif_is_virtual(vif))) {
        vr_pfree(pkt, VP_DROP_MISC);
        return RX_HANDLER_CONSUMED;
    }


    linux_enqueue_pkt_for_gro(skb, vif, l2_pkt);

    return RX_HANDLER_CONSUMED;
}

/*
 * vif_from_napi - given a NAPI structure, return the corresponding vif
 */
static struct vr_interface *
vif_from_napi(struct napi_struct *napi)
{
    int offset;
    struct vr_interface *vif;

    offset = offsetof(struct vr_interface, vr_napi);
    vif = (struct vr_interface *) (((char *)napi) - offset);

    return vif;
}

/*
 * vif_from_l2_napi - given a L2 NAPI structure, return the corresponding vif
 */
static struct vr_interface *
vif_from_l2_napi(struct napi_struct *napi)
{
    int offset;
    struct vr_interface *vif;

    offset = offsetof(struct vr_interface, vr_l2_napi);
    vif = (struct vr_interface *) (((char *)napi) - offset);

    return vif;
}


/*
 * vr_napi_poll - NAPI poll routine to receive packets and perform
 * GRO.
 */
static int
vr_napi_poll(struct napi_struct *napi, int budget)
{
    struct sk_buff *skb;
    struct vr_interface *vif;
    int quota = 0;
    struct vr_interface *gro_vif = NULL;
    struct vr_interface_stats *gro_vif_stats = NULL;
    struct sk_buff_head *head;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,2,0))
    /*
     * Return value of napi_gro_receive() changed across Linux versions.
     */
    int ret, napi_gro_err = NET_RX_DROP;
#else
    gro_result_t ret, napi_gro_err = GRO_DROP;
#endif


    if (napi->dev == pkt_gro_dev) {
        vif = vif_from_napi(napi);
        gro_vif = (struct vr_interface *)pkt_gro_dev->ml_priv;
        head = &vif->vr_skb_inputq;
    } else {
        vif = vif_from_l2_napi(napi);
        gro_vif = (struct vr_interface *)pkt_l2_gro_dev->ml_priv;
        head = &vif->vr_skb_l2_inputq;
    }

    if (gro_vif)
        gro_vif_stats = vif_get_stats(gro_vif, vr_get_cpu());

    while ((skb = skb_dequeue(head))) {
        vr_skb_set_rxhash(skb, 0);

        ret = napi_gro_receive(napi, skb);
        if (ret == napi_gro_err) {
            if (gro_vif_stats)
                gro_vif_stats->vis_ierrors++;
        }

        quota++;
        if (quota == budget) {
            break;
        }
    }

    if (quota != budget) {
        napi_complete(napi);

        return 0;
    }

    return budget;
}

struct vr_host_interface_ops vr_linux_interface_ops = {
    .hif_lock           =       linux_if_lock,
    .hif_unlock         =       linux_if_unlock,
    .hif_add            =       linux_if_add,
    .hif_del            =       linux_if_del,
    .hif_add_tap        =       linux_if_add_tap,
    .hif_del_tap        =       linux_if_del_tap,
    .hif_tx             =       linux_if_tx,
    .hif_rx             =       linux_if_rx,
    .hif_get_settings   =       linux_if_get_settings,
    .hif_get_mtu        =       linux_if_get_mtu,
    .hif_get_encap      =       linux_if_get_encap,
};

static int
linux_if_notifier(struct notifier_block * __unused,
        unsigned long event, void *arg)
{
    /* for now, get router id 0 */
    struct vrouter *router = vrouter_get(0);
    struct vr_interface *agent_if, *eth_if;
    struct net_device *dev;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0))
    struct netdev_notifier_info *info = (struct netdev_notifier_info *)arg;
    dev = info->dev;
#else
    dev = (struct net_device *)arg;
#endif

#ifdef CONFIG_NET_NS
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0))
    if (dev_net(dev) != &init_net) {
#else
    if (dev->nd_net != &init_net) {
#endif
        return NOTIFY_DONE;
    }
#endif

    if (!router)
        return NOTIFY_DONE;

    agent_if = router->vr_agent_if;

    if (event == NETDEV_UNREGISTER) {
        if (agent_if) {
            if (dev == (struct net_device *)agent_if->vif_os) {
                vif_detach(agent_if);
                agent_alive = false;
                /* try xconnecting all vhost interfaces */
                vhost_xconnect();
                return NOTIFY_OK;
            }
        }

        if ((eth_if = vif_find(router, dev->name)))
            vif_detach(eth_if);
        /* quite possible that there was no vif */
        vhost_detach_phys(dev);
    } else if (event == NETDEV_REGISTER) {
        if ((eth_if = vif_find(router, dev->name))) {
            eth_if->vif_os_idx = dev->ifindex;
            vif_attach(eth_if);
        }

        /* quite possible that there was no vif */
        vhost_attach_phys(dev);
    }

    return NOTIFY_DONE;
}


static struct notifier_block host_if_nb = {
    .notifier_call      =       linux_if_notifier,
};


void
vr_host_vif_init(struct vrouter *router)
{
    if (pkt_gro_dev)
        vr_gro_vif_add(router, pkt_gro_dev->ifindex,
                pkt_gro_dev->name, router->vr_max_interfaces - 1);

    if (pkt_l2_gro_dev)
        vr_gro_vif_add(router, pkt_l2_gro_dev->ifindex,
                pkt_l2_gro_dev->name, router->vr_max_interfaces - 2);
    return;
}

void
vr_host_interface_exit(void)
{
    unregister_netdevice_notifier(&host_if_nb);
    vhost_exit();
    linux_pkt_dev_free();

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39))
    if (vr_use_linux_br) {
        br_handle_frame_hook = NULL;
    } else {
        openvswitch_handle_frame_hook = NULL;
    }
#endif

    return;
}

static int
linux_pkt_dev_alloc(void)
{
    if (pkt_gro_dev == NULL) {
        pkt_gro_dev = linux_pkt_dev_init("pkt1", &pkt_gro_dev_setup,
                                         &pkt_gro_dev_rx_handler);
        if (pkt_gro_dev == NULL) {
            vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, 0);
            return -ENOMEM;
        }
    }

    if (pkt_l2_gro_dev == NULL) {
        pkt_l2_gro_dev = linux_pkt_dev_init("pkt3", &pkt_l2_gro_dev_setup,
                                         &pkt_gro_dev_rx_handler);
        if (pkt_l2_gro_dev == NULL) {
            vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, 0);
            return -ENOMEM;
        }
    }

    if (pkt_rps_dev == NULL) {
        pkt_rps_dev = linux_pkt_dev_init("pkt2", &pkt_rps_dev_setup,
                                        &pkt_rps_dev_rx_handler);
        if (pkt_rps_dev == NULL) {
            vr_module_error(-ENOMEM, __FUNCTION__, __LINE__, 0);
            return -ENOMEM;
        }
    }

    return 0;
}

/*
 * no error handling here. exit will be called in case of error returns
 * where proper cleanups are done
 */
struct vr_host_interface_ops *
vr_host_interface_init(void)
{
    int ret;

    ret = linux_pkt_dev_alloc();
    if (ret)
        return NULL;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39))
    if (vr_use_linux_br) {
        br_handle_frame_hook = vr_interface_bridge_hook;
    } else {
        openvswitch_handle_frame_hook = vr_interface_ovs_hook;
    }
#endif

    vhost_init();

    ret = register_netdevice_notifier(&host_if_nb);
    if (ret) {
        vr_module_error(ret, __FUNCTION__, __LINE__, 0);
        return NULL;
    }

    return &vr_linux_interface_ops;
}
