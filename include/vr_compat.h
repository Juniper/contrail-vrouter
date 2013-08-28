/*
 *  vr_compat.h - compatibility definitions
 *  
 *  Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VRCOMPAT_H__
#define __VRCOMPAT_H__

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,2,43))
typedef u64 netdev_features_t;
#endif

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,32))
static inline __u32
skb_get_rxhash(struct sk_buff *skb)
{
#ifndef CONFIG_XEN
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

#define VLAN_CFI_MASK	0x1000
#define VLAN_TAG_PRESENT VLAN_CFI_MASK
#define ARPHRD_VOID	0xFFFF

#define alloc_netdev_mqs(sizeof_priv, name, setup, count1, count2) \
	alloc_netdev_mq(sizeof_priv, name, setup, count1)

#if (RHEL_MAJOR != 6) && (RHEL_MINOR != 4) 

static inline void skb_reset_mac_len(struct sk_buff *skb)
{
        skb->mac_len = skb->network_header - skb->mac_header;
}

#endif

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
