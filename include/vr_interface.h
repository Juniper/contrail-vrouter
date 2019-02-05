/*
 * vr_interface.h --
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_INTERFACE_H__
#define __VR_INTERFACE_H__

#include "vr_defs.h"
#include "vr_types.h"
#include "vr_htable.h"
#include "vr_qos.h"
#include "vr_flow.h"
#include "vr_index_table.h"

/*
 * 2 interfaces/VM + maximum vlan interfaces. VR_MAX_INTERFACES needs to
 * be the same as VR_UVH_MAX_CLIENTS.
 */
#define VR_MAX_INTERFACES           (256 + 4096)

/* 
 * Default size for the interface bridge table.
 */
#define VIF_BRIDGE_ENTRIES      1024
#define VIF_BRIDGE_OENTRIES     512

#define VIF_TYPE_HOST               0
#define VIF_TYPE_AGENT              1
#define VIF_TYPE_PHYSICAL           2
#define VIF_TYPE_VIRTUAL            3
#define VIF_TYPE_XEN_LL_HOST        4
#define VIF_TYPE_GATEWAY            5
#define VIF_TYPE_VIRTUAL_VLAN       6
#define VIF_TYPE_STATS              7
#define VIF_TYPE_VLAN               8
#define VIF_TYPE_MONITORING         9
#define VIF_TYPE_MAX               10


#define vif_is_virtual(vif)         ((vif->vif_type == VIF_TYPE_VIRTUAL) ||\
                                        (vif->vif_type == VIF_TYPE_VIRTUAL_VLAN))
#define vif_is_fabric(vif)          (vif->vif_type == VIF_TYPE_PHYSICAL)
#define vif_is_vlan(vif)            ((vif->vif_type == VIF_TYPE_VIRTUAL_VLAN))

#define vif_is_tap(vif)             ((vif->vif_type == VIF_TYPE_VIRTUAL) ||\
                                        (vif->vif_type == VIF_TYPE_AGENT))

#define vif_is_vhost(vif)           ((vif->vif_type == VIF_TYPE_HOST) ||\
                                        (vif->vif_type == VIF_TYPE_XEN_LL_HOST) ||\
                                        (vif->vif_type == VIF_TYPE_GATEWAY))
#define vif_is_service(vif)         (vif->vif_flags & VIF_FLAG_SERVICE_IF)

#define vif_drop_new_flows(vif)     (vif->vif_flags & VIF_FLAG_DROP_NEW_FLOWS)

#define vif_needs_dev(vif)          ((vif->vif_type != VIF_TYPE_VIRTUAL_VLAN))

/* DPDK definitions */
#define vif_is_vm(vif)         ((vif->vif_type == VIF_TYPE_VIRTUAL) &&\
                                    (vif->vif_transport == VIF_TRANSPORT_PMD))
#define vif_is_namespace(vif)  ((vif->vif_type == VIF_TYPE_VIRTUAL) &&\
                                    (vif->vif_transport == VIF_TRANSPORT_ETH))
#define vif_is_agent(vif)      ((vif->vif_type == VIF_TYPE_AGENT) &&\
                                    (vif->vif_transport == VIF_TRANSPORT_SOCKET))
#define vif_is_monitoring(vif) (vif->vif_type == VIF_TYPE_MONITORING)


#define VR_INTERFACE_NAME_LEN       64
#define VIF_MAX_MIRROR_MD_SIZE      255

#define VIF_SRC_MACS                4

#define VIF_TRANSPORT_VIRTUAL       0
#define VIF_TRANSPORT_ETH           1
#define VIF_TRANSPORT_PMD           2
#define VIF_TRANSPORT_SOCKET        3

#define VR_IF_ADD                   0
#define VR_IF_DEL                   1

#define VIF_FLAG_POLICY_ENABLED     0x1
#define VIF_FLAG_XCONNECT           0x2
#define VIF_FLAG_SERVICE_IF         0x4
#define VIF_FLAG_MIRROR_RX          0x8
#define VIF_FLAG_MIRROR_TX          0x10
#define VIF_FLAG_TX_CSUM_OFFLOAD    0x20
#define VIF_FLAG_L3_ENABLED         0x40
#define VIF_FLAG_L2_ENABLED         0x80
#define VIF_FLAG_DHCP_ENABLED       0x100
/* The physical interface corresponds to a vhost interface */
#define VIF_FLAG_VHOST_PHYS         0x200
#define VIF_FLAG_PROMISCOUS         0x400
/* untagged packets should be treated as packets with tag 0 */
#define VIF_FLAG_NATIVE_VLAN_TAG    0x800
#define VIF_FLAG_NO_ARP_PROXY       0x1000
#define VIF_FLAG_PMD                0x2000
/* The physical interface supports hardware filtering */
#define VIF_FLAG_FILTERING_OFFLOAD  0x4000
/*
 * The interface is being monitored,
 * so we copy all the packets to another interface
 */
#define VIF_FLAG_MONITORED          0x8000
#define VIF_FLAG_UNKNOWN_UC_FLOOD   0x10000
#define VIF_FLAG_VLAN_OFFLOAD       0x20000
/*
 * The interface is marked to drop new incoming flows
 * marked by vrouter agent to enforce flow-limit
 */
#define VIF_FLAG_DROP_NEW_FLOWS     0x40000
#define VIF_FLAG_MAC_LEARN          0x80000
#define VIF_FLAG_MAC_PROXY          0x100000
#define VIF_FLAG_ETREE_ROOT         0x200000
#define VIF_FLAG_GRO_NEEDED         0x400000
#define VIF_FLAG_MRG_RXBUF          0x800000
#define VIF_FLAG_MIRROR_NOTAG       0x1000000
#define VIF_FLAG_IGMP_ENABLED       0x2000000

/* vrouter capabilities mask (cannot be changed by agent) */
#define VIF_VR_CAP_MASK (VIF_FLAG_TX_CSUM_OFFLOAD | \
                         VIF_FLAG_VLAN_OFFLOAD | \
                         VIF_FLAG_GRO_NEEDED | \
                         VIF_FLAG_MRG_RXBUF)

/* Only to be used from Agent/utility to request for Drop stats dump */
#define VIF_FLAG_GET_DROP_STATS    0x01

#define vif_mode_xconnect(vif)      (vif->vif_flags & VIF_FLAG_XCONNECT)
#define vif_dhcp_enabled(vif)       (vif->vif_flags & VIF_FLAG_DHCP_ENABLED)

#define VIF_VRF_TABLE_ENTRIES       1024
#define VIF_VRF_INVALID             ((unsigned short)-1)

#define VIF_ENCAP_TYPE_ETHER        1
#define VIF_ENCAP_TYPE_L3           2
/* This flag is used in identifying the IPSec VTI
   interface. VTI interfaces are L3 tunnel interfaces
   that enable route-based VPN. VTI device is created
   using iproute2's, <ip tunnel> command.
   IPSec kernel will write the decrypted packets, that
   match the source IP header and key to the matched
   VTI interface created with the same source IP.
*/
#define VIF_ENCAP_TYPE_L3_DECRYPT   3

typedef enum {
    MR_DROP,
    MR_FLOOD,
    MR_PROXY,
    MR_NOT_ME,
    MR_MIRROR,
    MR_TRAP_X,
    MR_XCONNECT,
} mac_response_t;

typedef enum {
    VHOSTUSER_CLIENT = 0,
    VHOSTUSER_SERVER,
}vhostuser_mode_t;

struct vr_interface_stats {
    uint64_t vis_ibytes;
    uint64_t vis_ipackets;
    uint64_t vis_ierrors;
    uint64_t vis_obytes;
    uint64_t vis_opackets;
    uint64_t vis_oerrors;
    /* queue counters */
    uint64_t vis_queue_ipackets;
    uint64_t *vis_queue_ierrors_to_lcore;
    uint64_t vis_queue_ierrors;
    uint64_t vis_queue_opackets;
    uint64_t vis_queue_oerrors;
    /* port counters */
    uint64_t vis_port_ipackets;
    uint64_t vis_port_ierrors;
    uint64_t vis_port_isyscalls;
    uint64_t vis_port_inombufs;
    uint64_t vis_port_opackets;
    uint64_t vis_port_oerrors;
    uint64_t vis_port_osyscalls;
    /* device counters */
    uint64_t vis_dev_ibytes;
    uint64_t vis_dev_ipackets;
    uint64_t vis_dev_ierrors;
    uint64_t vis_dev_inombufs;
    uint64_t vis_dev_obytes;
    uint64_t vis_dev_opackets;
    uint64_t vis_dev_oerrors;
};

struct vr_packet;

struct agent_send_params {
    unsigned short trap_reason;
    unsigned short trap_vrf;
    void *trap_param;
};

struct vr_df_trap_arg {
    unsigned int df_mtu;
    unsigned int df_flow_index;
};

struct vr_interface;
struct vr_forwarding_md;

struct vr_interface_driver {
    int     (*drv_add)(struct vr_interface *, vr_interface_req *);
    int     (*drv_change)(struct vr_interface *);
    int     (*drv_delete)(struct vr_interface *);
    int     (*drv_add_sub_interface)(struct vr_interface *,
            struct vr_interface *);
    int     (*drv_delete_sub_interface)(struct vr_interface *,
            struct vr_interface *);
};

struct vr_vrf_assign {
    int va_vrf;
    unsigned int va_nh_id;
};

#define VIF_FAT_FLOW_NUM_BITMAPS        (128)
#define VIF_FAT_FLOW_BITMAP_SIZE        (1024)
#define VIF_FAT_FLOW_PORTS_PER_BITMAP   (1024 / 2)
#define VIF_FAT_FLOW_BITMAP_BYTES       (VIF_FAT_FLOW_BITMAP_SIZE / 8)

#define VIF_FAT_FLOW_NOPROTO_INDEX  0
#define VIF_FAT_FLOW_TCP_INDEX      1
#define VIF_FAT_FLOW_UDP_INDEX      2
#define VIF_FAT_FLOW_SCTP_INDEX     3
#define VIF_FAT_FLOW_MAXPROTO_INDEX 4


#define VIF_FAT_FLOW_PROTOCOL_SHIFT     16
#define VIF_FAT_FLOW_PORT_DATA_SHIFT    24
#define VIF_FAT_FLOW_PORT_AGGR_INFO_SHIFT 24
#define VIF_FAT_FLOW_DATA_MASK           3
#define VIF_FAT_FLOW_PREFIX_AGGR_DATA_SHIFT 28

#define VIF_FAT_FLOW_PORT(p_p)          ((p_p) & 0xFFFF)
#define VIF_FAT_FLOW_PROTOCOL(p_p)      (((p_p) >> VIF_FAT_FLOW_PROTOCOL_SHIFT) & 0xFF)
#define VIF_FAT_FLOW_PORT_DATA(p_p)        (((p_p) >> VIF_FAT_FLOW_PORT_DATA_SHIFT) & 0x03)
#define VIF_FAT_FLOW_PORT_AGGR_INFO(p_p)   (((p_p) >> VIF_FAT_FLOW_PORT_AGGR_INFO_SHIFT))
#define VIF_FAT_FLOW_PREFIX_AGGR_DATA(p_p) (((p_p) >> VIF_FAT_FLOW_PREFIX_AGGR_DATA_SHIFT) & 0x0F)

#define VIF_FAT_FLOW_CFG_PORT_DATA(p_p)        ((p_p) & 0x0F)
#define VIF_FAT_FLOW_CFG_PREFIX_AGGR_DATA(p_p) ((p_p) >> 4)

#define VIF_FAT_FLOW_PORT_INVALID       0
#define VIF_FAT_FLOW_PORT_SIP_IGNORE    1
#define VIF_FAT_FLOW_PORT_DIP_IGNORE    2
#define VIF_FAT_FLOW_PORT_SET           3

#define FAT_FLOW_IPV4_EXCLUDE_LIST_MAX_SIZE    3   /* support for 3 internal addresses for now */
#define FAT_FLOW_IPV6_EXCLUDE_LIST_MAX_SIZE    3   /* support for 3 internal addresses for now */

#define FAT_FLOW_EXCLUDE_IPV4_PREFIX_LEN(a)  ((uint32_t) ((a) >> 32))
#define FAT_FLOW_EXCLUDE_IPV4_PREFIX(a)      ((uint32_t) ((a) & 0x00000000FFFFFFFF))

#define FAT_FLOW_IPV4_PLEN_TO_MASK(plen)   (htonl((0xFFFFFFFF << (32-(plen)))))

/* This enum should match with what is defined in agent */
typedef enum vr_fat_flow_prefix_aggr_ {
    VR_AGGREGATE_NONE = 0,
    VR_AGGREGATE_PREFIX_MIN_VAL = VR_AGGREGATE_NONE,
    VR_AGGREGATE_DST_IPV6,
    VR_AGGREGATE_SRC_IPV6,
    VR_AGGREGATE_SRC_DST_IPV6,
    VR_AGGREGATE_DST_IPV4,
    VR_AGGREGATE_SRC_IPV4,
    VR_AGGREGATE_SRC_DST_IPV4,
} vr_fat_flow_prefix_aggr_t;

typedef struct vr_fat_flow_cfg_ {
    uint8_t    protocol;
    uint16_t   port;
    uint8_t    port_aggr_info;
    uint64_t   src_prefix_h;
    uint64_t   src_prefix_l;
    uint8_t    src_prefix_mask;
    uint8_t    src_aggregate_plen;
    uint64_t   dst_prefix_h;
    uint64_t   dst_prefix_l;
    uint8_t    dst_prefix_mask;
    uint8_t    dst_aggregate_plen;
} vr_fat_flow_cfg_t;

typedef struct vr_fat_flow_prefix_rule_port_data_ {
#define PREFIX_RULE_TYPE_SINGLE_PREFIX   0x01 /* only src or dst rule */
#define PREFIX_RULE_TYPE_DUAL_PREFIX     0x02 /* src and dst rule */
#define PREFIX_RULE_HAS_IGNORE_DST       0x04 /* src rule with ign dst */
#define PREFIX_RULE_HAS_IGNORE_SRC       0x08 /* dst rule with ign src */

    uint8_t            rule_type;       /* rule type flags */
    uint8_t            aggr_plen;       /* Aggregate plen */
    struct ip_mtrie    *second_prefix;  /* Valid only in case of dual prefix rule */
} vr_fat_flow_prefix_rule_port_data_t;

typedef struct vr_fat_flow_prefix_rule_proto_info_ {
    vr_itable_t proto[VIF_FAT_FLOW_MAXPROTO_INDEX];
} vr_fat_flow_prefix_rule_proto_info_t;

typedef struct vr_fat_flow_prefix_rule_data_ {
    vr_fat_flow_prefix_rule_proto_info_t *proto_info;
    struct vr_fat_flow_prefix_rule_data_ *next;
} vr_fat_flow_prefix_rule_data_t;

struct vr_interface {
    unsigned int vif_flags;
    /*  Generation number is incrementing every time a vif is added. */
    unsigned int vif_gen;
    unsigned short vif_type;
    unsigned short vif_rid;
    /*
     * unsigned short does not cut it, because initial value for
     * each entry in the table is -1. negative value of table
     * entries is also vital for table_users calculation.
     */
    unsigned short vif_nh_id;
    unsigned short vif_idx;
    unsigned short vif_vrf;
    unsigned short vif_mtu;
    unsigned short vif_vlan_id;
    unsigned short vif_ovlan_id;

    struct vrouter *vif_router;
    struct vr_interface_stats *vif_stats;
    void *vif_os;
    int (*vif_tx)(struct vr_interface *, struct vr_packet *,
            struct vr_forwarding_md *);
    /*
     * we are forced to pass the final argument, vlan id, since linux
     * untags the packet and stores the id in skb member. with no space
     * in vr_packet to add more fields (unless, we delink vr_packet from
     * skb), the only way left is to pass the id as an argument. sucks
     * for sure...
     */
    int (*vif_rx)(struct vr_interface *, struct vr_packet *, unsigned short);

    int (*vif_set_rewrite)(struct vr_interface *, struct vr_packet **,
            struct vr_forwarding_md *, unsigned char *, unsigned short);
    uint8_t **vif_fat_flow_no_prefix_rules[VIF_FAT_FLOW_MAXPROTO_INDEX];
    struct ip_mtrie    *vif_fat_flow_v4_src_prefix_rules;
    struct ip_mtrie    *vif_fat_flow_v4_dst_prefix_rules;
    struct ip_mtrie    *vif_fat_flow_v6_src_prefix_rules;
    struct ip_mtrie    *vif_fat_flow_v6_dst_prefix_rules;
    vr_fat_flow_prefix_rule_data_t *vif_fat_flow_rule_data_list;
    vr_fat_flow_cfg_t  *fat_flow_cfg;
    uint16_t           fat_flow_cfg_size;
    /* Total number of no prefix and prefix based rules */
    uint16_t           fat_flow_num_rules[VIF_FAT_FLOW_MAXPROTO_INDEX];
    unsigned char vif_mac[VR_ETHER_ALEN];
    uint8_t vif_transport;
    uint8_t vif_mirror_id;
#ifdef __KERNEL__
#if defined(__linux__)
    struct napi_struct vr_napi;
    struct napi_struct vr_l2_napi;
    struct sk_buff_head vr_skb_inputq;
    struct sk_buff_head vr_skb_l2_inputq;
#elif defined(__FreeBSD__)
    struct mbuf;
    void (*saved_if_input) (struct ifnet *, struct mbuf *);
#elif defined(_WIN32)
    NDIS_SWITCH_PORT_ID vif_port;
    NDIS_SWITCH_NIC_INDEX vif_nic;
    GUID vif_guid;
#endif
#endif
    /* Big and less frequently used fields. */
    struct vr_interface *vif_parent;
    struct vr_interface *vif_bridge;
    unsigned int vif_users;
    unsigned int vif_os_idx;

    struct vr_vrf_assign *vif_vrf_table;
    int (*vif_send)(struct vr_interface *, struct vr_packet *, void *);
    mac_response_t (*vif_mac_request)(struct vr_interface *,
            struct vr_packet *, struct vr_forwarding_md *, unsigned char *);
    struct vr_interface **vif_sub_interfaces;
    struct vr_interface_driver *vif_driver;
    unsigned char *vif_src_mac;
    uint8_t *vif_bridge_table_lock;
    vr_htable_t vif_btable;
    unsigned char vif_rewrite[VR_ETHER_HLEN];
    int16_t vif_qos_map_index;
    unsigned char vif_name[VR_INTERFACE_NAME_LEN];
    uint64_t *vif_drop_stats;
    /*
     * The list of hardware queues that will be used in this NIC.
     * 'agent' reads the configuration and lets us know the list.
     * We need this information to bind the specific queues to
     * each forwarding lcores in DPDK.
     */
    uint16_t *vif_hw_queues;
    struct vr_btable *vif_pcpu_drop_stats;
    unsigned char *vif_in_mirror_md;
    unsigned char *vif_out_mirror_md;
    unsigned char vif_in_mirror_md_len;
    unsigned char vif_in_mirror_md_size;
    unsigned char vif_out_mirror_md_len;
    unsigned char vif_out_mirror_md_size;
    unsigned short vif_vrf_table_users;
    /* the number of hardware queues. from agent configuration */
    unsigned short vif_num_hw_queues;
    void *vif_queue_host_data;
    unsigned int  vif_ip;
    unsigned int vif_isid;
    uint8_t vif_ip6[VR_IP6_ADDRESS_LEN];
    uint8_t vif_pbb_mac[VR_ETHER_ALEN];
    uint16_t vif_mcast_vrf;
    vhostuser_mode_t vif_vhostuser_mode;
    /* fat flow exclude prefix list for v4 & v6 */
    uint64_t vif_fat_flow_ipv6_high_exclude_list[FAT_FLOW_IPV6_EXCLUDE_LIST_MAX_SIZE];
    uint64_t vif_fat_flow_ipv6_low_exclude_list[FAT_FLOW_IPV6_EXCLUDE_LIST_MAX_SIZE];
    uint32_t vif_fat_flow_ipv4_exclude_list[FAT_FLOW_IPV4_EXCLUDE_LIST_MAX_SIZE];
    uint8_t vif_fat_flow_ipv6_exclude_plen_list[FAT_FLOW_IPV6_EXCLUDE_LIST_MAX_SIZE];
    uint8_t vif_fat_flow_ipv4_exclude_plen_list[FAT_FLOW_IPV4_EXCLUDE_LIST_MAX_SIZE];
    uint8_t vif_fat_flow_ipv6_exclude_list_size;
    uint8_t vif_fat_flow_ipv4_exclude_list_size;
};

struct vr_interface_settings {
    uint32_t vis_speed;
    uint32_t vis_duplex;
};

struct vr_host_interface_ops {
    void (*hif_lock)(void);
    void (*hif_unlock)(void);
    int (*hif_add)(struct vr_interface *);
    int (*hif_del)(struct vr_interface *);
    int (*hif_add_tap)(struct vr_interface *);
    int (*hif_del_tap)(struct vr_interface *);
    int (*hif_tx)(struct vr_interface *, struct vr_packet *);
    int (*hif_rx)(struct vr_interface *, struct vr_packet *);
    int (*hif_get_settings)(struct vr_interface *,
            struct vr_interface_settings *);
    unsigned int (*hif_get_mtu)(struct vr_interface *);
    unsigned short (*hif_get_encap)(struct vr_interface *);
    void (*hif_stats_update)(struct vr_interface *, unsigned int);
};

extern int vr_interface_init(struct vrouter *);
extern void vr_interface_exit(struct vrouter *, bool);
extern void vr_interface_shut(struct vrouter *);
extern struct vr_interface *vrouter_get_interface(unsigned int, unsigned int);
extern struct vr_interface *__vrouter_get_interface(struct vrouter *, unsigned int);
extern void vrouter_put_interface(struct vr_interface *);
extern int vr_interface_dump_wrapper(vr_interface_req *);
extern int vr_interface_add(vr_interface_req *, bool);

extern void vif_attach(struct vr_interface *vif);
extern void vif_detach(struct vr_interface *vif);
extern int vif_delete(struct vr_interface *);
extern struct vr_interface *vif_find(struct vrouter *, char *);
extern unsigned int vif_get_mtu(struct vr_interface *);
extern void vif_set_xconnect(struct vr_interface *);
extern void vif_remove_xconnect(struct vr_interface *);
extern int vif_xconnect(struct vr_interface *, struct vr_packet *,
        struct vr_forwarding_md *);
extern void vif_drop_pkt(struct vr_interface *, struct vr_packet *, bool);
extern int vif_vrf_table_get(struct vr_interface *, vr_vrf_assign_req *);
extern unsigned int vif_vrf_table_get_nh(struct vr_interface *, unsigned short);
extern int vif_vrf_table_set(struct vr_interface *, unsigned int,
        int, unsigned int);
extern unsigned int vr_interface_req_get_size(void *);

#if defined(__linux__) && defined(__KERNEL__)
extern void vr_set_vif_ptr(struct net_device *dev, void *vif);
#endif

extern uint16_t vif_fat_flow_lookup(int incoming_vif, struct vr_interface *vif, uint8_t proto,
                    uint16_t sport, uint16_t dport, unsigned int *saddr, unsigned int *daddr,
                    unsigned char *ip6_src, unsigned char *ip6_dst);
extern unsigned int vr_interface_req_get_size(void *);
#endif /* __VR_INTERFACE_H__ */
