/*
 *  vr_compat.h - compatibility definitions
 *  
 *  Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VRCOMPAT_H__
#define __VRCOMPAT_H__

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0))
#if (! (defined(RHEL_MAJOR) && defined(RHEL_MINOR)  && \
           (RHEL_MAJOR == 6) && (RHEL_MINOR == 5)))
typedef u64 netdev_features_t;
#endif
#endif

/*
 * As per lxr, skb_get_rxhash exists in 3.13 versions and disappeared in
 * 3.14. We do not know of in between versions. However, the ubuntu
 * sources for 3.13.0-32 does not have it (for which the LINUX_VERSION
 * CODE is 199947, which corresponds to 3.13.11) and hence the following.
 *
 * But then in 3.13.0-36, ubuntu did
 *
 * #define skb_get_rxhash skb_get_hash
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,11)) && \
                           !(defined(skb_get_rxhash))
static inline __u32
skb_get_rxhash(struct sk_buff *skb)
{
    return skb_get_hash(skb);
}
#endif

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
static inline __u32
skb_get_rxhash(struct sk_buff *skb)
{
#if defined(RHEL_MAJOR) && defined(RHEL_MINOR)  && \
           (RHEL_MAJOR == 6) && (RHEL_MINOR == 4)
    struct iphdr *ip;
    u32 ports = 0;

    if (skb->rxhash) {
        return skb->rxhash;
    }

    if (skb->protocol != (htons(ETH_P_IP))) {
        return 0;
    }

    if (!pskb_may_pull(skb, sizeof(*ip))) {
        return 0;
    }

    ip = (struct iphdr *) skb->data;
    switch (ip->protocol) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
            if (vr_ip_transport_header_valid((struct vr_ip *) ip)) {
                /*
                 * Not a fragment, so pull in the source and dest ports
                 */
                if (pskb_may_pull(skb, ip->ihl*4 + 4)) {
                    ports = *((u32 *) (skb->data + (ip->ihl*4)));
                }
            }

            break;

        default:
            break;
    }

    if (hashrnd_inited == 0) {
        get_random_bytes(&vr_hashrnd, sizeof(vr_hashrnd));
        hashrnd_inited = 1;
    }

    skb->rxhash = jhash_3words(ip->saddr, ip->daddr, ports, vr_hashrnd) >> 16;
    if (!skb->rxhash) {
        skb->rxhash = 1;
    }

    return skb->rxhash;

#else
    return 0;
#endif
}

#if (RHEL_MAJOR != 6) && (RHEL_MINOR != 4) && defined(CONFIG_XEN)
static inline struct page *skb_frag_page(const skb_frag_t *frag)
{
        return frag->page;
}

static inline unsigned int skb_frag_size(const skb_frag_t *frag)
{
        return frag->size;
}

static inline void skb_frag_size_sub(skb_frag_t *frag, int delta)
{
        frag->size -= delta;
}
    
#endif
    
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39))
enum rx_handler_result {
	RX_HANDLER_CONSUMED,
	RX_HANDLER_ANOTHER,
	RX_HANDLER_EXACT,
	RX_HANDLER_PASS,
};

typedef enum rx_handler_result rx_handler_result_t;

#define VLAN_CFI_MASK    0x1000
#define VLAN_TAG_PRESENT VLAN_CFI_MASK
#define ARPHRD_VOID    0xFFFF

#if (RHEL_MAJOR != 6) && (RHEL_MINOR != 4) 

#define alloc_netdev_mqs(sizeof_priv, name, setup, count1, count2) \
        alloc_netdev_mq(sizeof_priv, name, setup, count1)

static inline void skb_reset_mac_len(struct sk_buff *skb)
{
        skb->mac_len = skb->network_header - skb->mac_header;
}

#endif

#ifndef ISRHOSKERNEL
#if (! (defined(RHEL_MAJOR) && defined(RHEL_MINOR)  && \
           (RHEL_MAJOR == 6) && (RHEL_MINOR == 5)))
static bool can_checksum_protocol(netdev_features_t features, __be16 protocol)
{
        return ((features & NETIF_F_GEN_CSUM) ||
                ((features & NETIF_F_V4_CSUM) &&
                 protocol == htons(ETH_P_IP)) ||
                ((features & NETIF_F_V6_CSUM) &&
                 protocol == htons(ETH_P_IPV6)) ||
                ((features & NETIF_F_FCOE_CRC) &&
                 protocol == htons(ETH_P_FCOE)));
}

static netdev_features_t harmonize_features(struct sk_buff *skb,
        __be16 protocol, netdev_features_t features)
{
        if (skb->ip_summed != CHECKSUM_NONE &&
            !can_checksum_protocol(features, protocol)) {
                features &= ~NETIF_F_ALL_CSUM;
                features &= ~NETIF_F_SG;
        }

        return features;
}

static inline
netdev_features_t netif_skb_features(struct sk_buff *skb)
{
        __be16 protocol = skb->protocol;
        netdev_features_t features = skb->dev->features;

        features &= ~NETIF_F_GSO_MASK;

        if (protocol == htons(ETH_P_8021Q)) {
                struct vlan_ethhdr *veh = (struct vlan_ethhdr *)skb->data;
                protocol = veh->h_vlan_encapsulated_proto;
        } else if (!vlan_tx_tag_present(skb)) {
                return harmonize_features(skb, protocol, features);
        }

        features &= (skb->dev->vlan_features | NETIF_F_HW_VLAN_TX);

        if (protocol != htons(ETH_P_8021Q)) {
                return harmonize_features(skb, protocol, features);
        } else {
                features &= NETIF_F_SG | NETIF_F_HIGHDMA | NETIF_F_FRAGLIST |
                                NETIF_F_GEN_CSUM | NETIF_F_HW_VLAN_TX;
                return harmonize_features(skb, protocol, features);
        }
}
#endif

#endif

#endif

#endif
