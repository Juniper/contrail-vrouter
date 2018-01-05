/*
 * vrouter.h -- vrouter helper
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VROUTER_H__
#define __VROUTER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "sandesh.h"
#include "vr_types.h"
#include "vr_interface.h"
#include "vr_qos.h"
#include "vr_flow.h"
#include "vr_bridge.h"
#include "vr_interface.h"
#include "vr_nexthop.h"
#include "vr_route.h"
#include "vr_response.h"
#include "vr_mpls.h"
#include "vr_index_table.h"
#include "vr_mem.h"

#define VR_NATIVE_VRF       0
#define VR_UNIX_PATH_MAX    108
#define VR_MAX_CPUS         64

#define VR_CPU_MASK     0xff
extern unsigned int vr_num_cpus;

#define VR_LOGTYPE_VROUTER  (1U << 0)
#define VR_LOGTYPE_USOCK    (1U << 1)
#define VR_LOGTYPE_UVHOST   (1U << 2)
#define VR_LOGTYPE_DPCORE   (1U << 3)

#define VR_LOG_EMERG    1U
#define VR_LOG_ALERT    2U
#define VR_LOG_CRIT     3U
#define VR_LOG_ERR      4U
#define VR_LOG_WARNING  5U
#define VR_LOG_NOTICE   6U
#define VR_LOG_INFO     7U
#define VR_LOG_DEBUG    8U

enum vr_malloc_objects_t {
    VR_ASSEMBLER_TABLE_OBJECT,
    VR_BRIDGE_MAC_OBJECT,
    VR_BRIDGE_TABLE_DATA_OBJECT,
    VR_BTABLE_OBJECT,
    VR_BUILD_INFO_OBJECT,
    VR_DEFER_OBJECT,
    VR_DROP_STATS_OBJECT,
    VR_DROP_STATS_REQ_OBJECT,
    VR_FLOW_QUEUE_OBJECT,
    VR_FLOW_REQ_OBJECT,
    VR_FLOW_REQ_PATH_OBJECT,
    VR_FLOW_HOLD_STAT_OBJECT,
    VR_FLOW_LINK_LOCAL_OBJECT,
    VR_FLOW_METADATA_OBJECT,
    VR_FLOW_DEFER_DATA_OBJECT,
    VR_FLOW_TABLE_DATA_OBJECT,
    VR_FLOW_TABLE_INFO_OBJECT,
    VR_FRAGMENT_OBJECT,
    VR_FRAGMENT_QUEUE_OBJECT,
    VR_FRAGMENT_QUEUE_ELEMENT_OBJECT,
    VR_FRAGMENT_SCANNER_OBJECT,
    VR_HPACKET_POOL_OBJECT,
    VR_HTABLE_OBJECT,
    VR_INTERFACE_OBJECT,
    VR_INTERFACE_BRIDGE_LOCK_OBJECT,
    VR_INTERFACE_FAT_FLOW_CONFIG_OBJECT,
    VR_INTERFACE_MAC_OBJECT,
    VR_INTERFACE_MIRROR_META_OBJECT,
    VR_INTERFACE_REQ_OBJECT,
    VR_INTERFACE_REQ_BRIDGE_ID_OBJECT,
    VR_INTERFACE_REQ_MAC_OBJECT,
    VR_INTERFACE_REQ_MIRROR_META_OBJECT,
    VR_INTERFACE_REQ_NAME_OBJECT,
    VR_INTERFACE_REQ_PBB_MAC_OBJECT,
    VR_INTERFACE_REQ_TO_LCORE_ERRORS_OBJECT,
    VR_INTERFACE_STATS_OBJECT,
    VR_INTERFACE_TABLE_OBJECT,
    VR_INTERFACE_TO_LCORE_ERRORS_OBJECT,
    VR_INTERFACE_VRF_TABLE_OBJECT,
    VR_INTERFACE_QUEUE_OBJECT,
    VR_ITABLE_OBJECT,
    VR_LOG_TYPES_OBJECT,
    VR_MALLOC_OBJECT,
    VR_MESSAGE_OBJECT,
    VR_MESSAGE_RESPONSE_OBJECT,
    VR_MESSAGE_DUMP_OBJECT,
    VR_MEM_OBJECT,
    VR_MEM_STATS_REQ_OBJECT,
    VR_MIRROR_OBJECT,
    VR_MIRROR_TABLE_OBJECT,
    VR_MIRROR_META_OBJECT,
    VR_MTRIE_OBJECT,
    VR_MTRIE_BUCKET_OBJECT,
    VR_MTRIE_STATS_OBJECT,
    VR_MTRIE_TABLE_OBJECT,
    VR_NETWORK_ADDRESS_OBJECT,
    VR_NEXTHOP_OBJECT,
    VR_NEXTHOP_COMPONENT_OBJECT,
    VR_NEXTHOP_REQ_BMAC_OBJECT,
    VR_NEXTHOP_REQ_LIST_OBJECT,
    VR_NEXTHOP_REQ_ENCAP_OBJECT,
    VR_NEXTHOP_REQ_OBJECT,
    VR_ROUTE_TABLE_OBJECT,
    VR_ROUTE_REQ_MAC_OBJECT,
    VR_TIMER_OBJECT,
    VR_USOCK_OBJECT,
    VR_USOCK_POLL_OBJECT,
    VR_USOCK_BUF_OBJECT,
    VR_USOCK_IOVEC_OBJECT,
    VR_VROUTER_REQ_OBJECT,
    VR_BITMAP_OBJECT,
    VR_QOS_MAP_OBJECT,
    VR_FC_OBJECT,
    VR_VROUTER_MAX_OBJECT,
};

extern int vr_perfr;
extern int vr_mudp;
extern int vr_perfs;
extern int vr_perfp;
extern int vr_perfr1, vr_perfr2, vr_perfr3;
extern int vr_perfq1, vr_perfq2, vr_perfq3;
extern int vr_from_vm_mss_adj;
extern int vr_to_vm_mss_adj;
extern int vr_udp_coff;
extern unsigned int vr_flow_hold_limit;
extern int vr_use_linux_br;
extern int hashrnd_inited;
extern uint32_t vr_hashrnd;
extern unsigned int vr_priority_tagging;

#define CONTAINER_OF(member, struct_type, pointer) \
    ((struct_type *)((uintptr_t)pointer - \
                (uintptr_t)&(((struct_type *)0)->member)))


typedef void(*vr_defer_cb)(struct vrouter *router, void *user_data);

struct vr_ip;

struct vr_timer {
    void (*vt_timer)(void *);
    void *vt_vr_arg;
    void *vt_os_arg;
    unsigned int vt_stop_timer;
    unsigned int vt_msecs;
};

struct host_os {
    int (*hos_printf)(const char *, ...) __attribute__format__(printf, 1, 2);
    void *(*hos_malloc)(unsigned int, unsigned int);
    void *(*hos_zalloc)(unsigned int, unsigned int);
    void (*hos_free)(void *, unsigned int);
    uint64_t (*hos_vtop)(void *);
    void *(*hos_page_alloc)(unsigned int);
    void (*hos_page_free)(void *, unsigned int);

    struct vr_packet *(*hos_palloc)(unsigned int);
    struct vr_packet *(*hos_palloc_head)(struct vr_packet *, unsigned int);
    struct vr_packet *(*hos_pexpand_head)(struct vr_packet *, unsigned int);
    void (*hos_pfree)(struct vr_packet *, unsigned short);
    struct vr_packet *(*hos_pclone)(struct vr_packet *);
    void (*hos_preset)(struct vr_packet *);
    int (*hos_pcopy)(unsigned char *, struct vr_packet *, unsigned int,
            unsigned int);
    unsigned short (*hos_pfrag_len)(struct vr_packet *);
    unsigned short (*hos_phead_len)(struct vr_packet *);
    void (*hos_pset_data)(struct vr_packet *, unsigned short);
    unsigned int (*hos_pgso_size)(struct vr_packet *);

    unsigned int (*hos_get_cpu)(void);
    int (*hos_schedule_work)(unsigned int, void (*)(void *), void *);
    void (*hos_delay_op)(void);
    void (*hos_defer)(struct vrouter *, vr_defer_cb, void *);
    void *(*hos_get_defer_data)(unsigned int);
    void (*hos_put_defer_data)(void *);
    void (*hos_get_time)(uint64_t *, uint64_t *);
    void (*hos_get_mono_time)(uint64_t *, uint64_t *);
    int (*hos_create_timer)(struct vr_timer *);
    int (*hos_restart_timer)(struct vr_timer *);
    void (*hos_delete_timer)(struct vr_timer *);

    void *(*hos_network_header)(struct vr_packet *);
    void *(*hos_inner_network_header)(struct vr_packet *);
    void *(*hos_data_at_offset)(struct vr_packet *, unsigned short);
    void *(*hos_pheader_pointer)(struct vr_packet *, unsigned short,
                                 void *);
    int  (*hos_pull_inner_headers)(struct vr_packet *,
                                   unsigned short, unsigned short *,
                                   int (*is_label_l2)(unsigned int,
                                       unsigned int, unsigned short *));
    int  (*hos_pcow)(struct vr_packet **, unsigned short);
    uint16_t (*hos_get_udp_src_port)(struct vr_packet *,
                                     struct vr_forwarding_md *,
                                     unsigned short);
    int (*hos_pkt_from_vm_tcp_mss_adj)(struct vr_packet *, unsigned short);
    int  (*hos_pull_inner_headers_fast)(struct vr_packet *,
                                        unsigned char, int
                                        (*is_label_l2)(unsigned int,
                                            unsigned int, unsigned short *),
                                        int *, int *);
    int (*hos_pkt_may_pull)(struct vr_packet *, unsigned int);
    int (*hos_gro_process)(struct vr_packet *, struct vr_interface *, bool);
    void (*hos_add_mpls)(struct vrouter *, unsigned);
    void (*hos_del_mpls)(struct vrouter *, unsigned);
    int (*hos_enqueue_to_assembler)(struct vrouter *, struct vr_packet *,
            struct vr_forwarding_md *);
    void (*hos_set_log_level)(unsigned int vr_log_level);
    void (*hos_set_log_type)(unsigned int vr_log_type, int enable);
    unsigned int (*hos_get_log_level)(void);
    unsigned int *(*hos_get_enabled_log_types)(int *);
    void (*hos_soft_reset)(struct vrouter *);
    int (*hos_is_frag_limit_exceeded)(void);
    void (*hos_register_nic)(struct vr_interface* vif, vr_interface_req* vifr);
    bool hos_nl_broadcast_supported;
    int (*hos_huge_page_config)(uint64_t *, int, int *, int);
    void *(*hos_huge_page_mem_get)(int);
};

#define vr_printf                       vrouter_host->hos_printf
#define vr_malloc                       vrouter_host->hos_malloc
#define vr_zalloc                       vrouter_host->hos_zalloc
#define vr_free                         vrouter_host->hos_free
#define vr_vtop                         vrouter_host->hos_vtop
#define vr_page_alloc                   vrouter_host->hos_page_alloc
#define vr_page_free                    vrouter_host->hos_page_free
#define vr_palloc                       vrouter_host->hos_palloc
#define vr_palloc_head                  vrouter_host->hos_palloc_head
#define vr_pexpand_head                 vrouter_host->hos_pexpand_head
#define vr_pfree                        vrouter_host->hos_pfree
#define vr_pclone                       vrouter_host->hos_pclone
#define vr_preset                       vrouter_host->hos_preset
#define vr_pcopy                        vrouter_host->hos_pcopy
#define vr_pfrag_len                    vrouter_host->hos_pfrag_len
#define vr_phead_len                    vrouter_host->hos_phead_len
#define vr_pgso_size                    vrouter_host->hos_pgso_size
#define vr_pset_data                    vrouter_host->hos_pset_data
#define vr_get_cpu                      vrouter_host->hos_get_cpu
#define vr_schedule_work                vrouter_host->hos_schedule_work
#define vr_delay_op                     vrouter_host->hos_delay_op
#define vr_defer                        vrouter_host->hos_defer
#define vr_get_defer_data               vrouter_host->hos_get_defer_data
#define vr_put_defer_data               vrouter_host->hos_put_defer_data
#define vr_get_time                     vrouter_host->hos_get_time
#define vr_get_mono_time                vrouter_host->hos_get_mono_time
#define vr_create_timer                 vrouter_host->hos_create_timer
#define vr_restart_timer                vrouter_host->hos_restart_timer
#define vr_delete_timer                 vrouter_host->hos_delete_timer
#define vr_network_header               vrouter_host->hos_network_header
#define vr_inner_network_header         vrouter_host->hos_inner_network_header
#define vr_data_at_offset               vrouter_host->hos_data_at_offset
#define vr_pheader_pointer              vrouter_host->hos_pheader_pointer
#define vr_pull_inner_headers           vrouter_host->hos_pull_inner_headers
#define vr_pcow                         vrouter_host->hos_pcow
#define vr_pull_inner_headers_fast      vrouter_host->hos_pull_inner_headers_fast
#define vr_get_udp_src_port             vrouter_host->hos_get_udp_src_port
#define vr_pkt_from_vm_tcp_mss_adj      vrouter_host->hos_pkt_from_vm_tcp_mss_adj
#define vr_pkt_may_pull                 vrouter_host->hos_pkt_may_pull
#define vr_gro_process                  vrouter_host->hos_gro_process
#define vr_enqueue_to_assembler         vrouter_host->hos_enqueue_to_assembler
#define vr_set_log_level                vrouter_host->hos_set_log_level
#define vr_set_log_type                 vrouter_host->hos_set_log_type
#define vr_get_log_level                vrouter_host->hos_get_log_level
#define vr_get_enabled_log_types        vrouter_host->hos_get_enabled_log_types
#define vr_soft_reset                   vrouter_host->hos_soft_reset
#define vr_register_nic                 vrouter_host->hos_register_nic
#define vr_nl_broadcast_supported       vrouter_host->hos_nl_broadcast_supported
#define vr_huge_page_config             vrouter_host->hos_huge_page_config
#define vr_huge_page_mem_get            vrouter_host->hos_huge_page_mem_get

extern struct host_os *vrouter_host;

struct vr_malloc_stats {
    int64_t ms_size;
    int64_t ms_alloc;
    int64_t ms_free;
};

#define VMM_STATE_ALLOCED   1

extern unsigned int vr_memory_alloc_checks;

__attribute__packed__open__
struct vr_malloc_md {
    char vmm_magic[3];
    uint8_t vmm_state;
    unsigned int vmm_object;
} __attribute__packed__close__;

static inline void
vr_malloc_md_set(void *mem, unsigned int object)
{
    struct vr_malloc_md *vmm;

    vmm = (struct vr_malloc_md *)mem;
    strncpy(vmm->vmm_magic, "MEM", sizeof(vmm->vmm_magic));
    vmm->vmm_state = VMM_STATE_ALLOCED;
    vmm->vmm_object = object;

    return;
}

static inline void
vr_malloc_md_check(void *mem, unsigned int object)
{
    struct vr_malloc_md *vmm;

    vmm = (struct vr_malloc_md *)((uint8_t *)mem - sizeof(*vmm));
    if (vmm->vmm_state != VMM_STATE_ALLOCED)
        goto bug;
    if (strncmp(vmm->vmm_magic, "MEM", sizeof(vmm->vmm_magic)))
        goto bug;
    if (vmm->vmm_object != object)
        goto bug;

    memset(vmm, 0, sizeof(*vmm));

    return;
bug:
    vr_printf("vrouter BUG: Inconsistent state of memory %p\n", mem);
    vr_printf("vrouter BUG: state %u object %u expected %u\n",
            vmm->vmm_state, vmm->vmm_object, object);
    vr_printf("vrouter BUG: MAGIC %c%c%c\n",
            vmm->vmm_magic[0], vmm->vmm_magic[1], vmm->vmm_magic[2]);
    memset(vmm, 0, sizeof(*vmm));
    return;
}

struct vrouter {
    unsigned char vr_vrrp_mac[VR_ETHER_ALEN];
    unsigned char vr_mac[VR_ETHER_ALEN];
    unsigned int vr_ip;

    struct vr_interface **vr_interfaces;
    /*  Generation number is incrementing every time it is used. */
    unsigned int vr_generation_num;
    unsigned int vr_max_interfaces;

    unsigned int vr_max_nexthops;
    struct vr_btable *vr_nexthops;
    struct vr_rtable *vr_inet_rtable;
    struct vr_rtable *vr_inet_mcast_rtable;
    struct vr_rtable *vr_bridge_rtable;

    vr_htable_t vr_flow_table;
    struct vr_flow_table_info *vr_flow_table_info;
    unsigned int vr_flow_table_info_size;

    unsigned int vr_max_labels;
    struct vr_btable *vr_ilm;

    unsigned int vr_max_vrfs;
    unsigned int vr_max_mirror_indices;
    struct vr_mirror_entry **vr_mirrors;
    vr_itable_t vr_mirror_md;
    vr_itable_t vr_vxlan_table;

    vr_htable_t vr_fragment_table;
    struct vr_timer *vr_fragment_table_scanner;

    uint64_t **vr_pdrop_stats;
    struct vr_malloc_stats **vr_malloc_stats;

    uint16_t vr_link_local_ports_size;
    unsigned char *vr_link_local_ports;

    struct vr_forwarding_class **vr_qos_map;
    struct vr_forwarding_class *vr_fc_table;

    struct vr_interface *vr_agent_if;
    struct vr_interface *vr_host_if;
    struct vr_interface *vr_eth_if;
};

struct vr_defer_data {
    void *vdd_data;
};

extern volatile bool vr_not_ready;

extern struct vrouter *vrouter_get(unsigned int);
extern unsigned int vrouter_generation_num_get(struct vrouter *router);

extern int vrouter_init(void);
extern void vrouter_exit(bool);
extern int vr_module_error(int, const char *, int, int);
extern int vhost_init(void);

#ifdef __cplusplus
}
#endif

#endif /* __VROUTER_H__ */
