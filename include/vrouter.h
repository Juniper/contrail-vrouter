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
#include "vr_flow.h"
#include "vr_nexthop.h"
#include "vr_route.h"
#include "vr_flow.h"
#include "vr_response.h"
#include "vr_mpls.h"
#include "vr_index_table.h"

#define VR_NATIVE_VRF       0

#define VR_CPU_MASK     0xff
extern unsigned int vr_num_cpus;

extern int vr_perfr;
extern int vr_mudp;
extern int vr_perfs;
extern int vr_perfp;
extern int vr_perfr1, vr_perfr2, vr_perfr3;
extern int vr_perfq1, vr_perfq2, vr_perfq3;
extern int vr_from_vm_mss_adj;
extern int vr_to_vm_mss_adj;
extern int vr_udp_coff;
extern int vr_use_linux_br;
extern int hashrnd_inited;
extern uint32_t vr_hashrnd;

#define CONTAINER_OF(member, struct_type, pointer) \
    ((struct_type *)((unsigned long)pointer - \
                (size_t)&(((struct_type *)0)->member)))


typedef void(*vr_defer_cb)(struct vrouter *router, void *user_data);

struct vr_ip;

struct vr_timer {
    void (*vt_timer)(void *);
    void *vt_vr_arg;
    void *vt_os_arg;
    unsigned int vt_msecs;
};

struct host_os {
    void *(*hos_malloc)(unsigned int);
    void *(*hos_zalloc)(unsigned int);
    void (*hos_free)(void *);
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
    void (*hos_schedule_work)(unsigned int, void (*)(void *), void *);
    void (*hos_delay_op)(void);
    void (*hos_defer)(struct vrouter *, vr_defer_cb, void *);
    void *(*hos_get_defer_data)(unsigned int);
    void (*hos_put_defer_data)(void *);
    void (*hos_get_time)(unsigned int*, unsigned int *);
    void (*hos_get_mono_time)(unsigned int*, unsigned int *);
    int (*hos_create_timer)(struct vr_timer *);
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
    int  (*hos_pcow)(struct vr_packet *, unsigned short); 
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
};

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

struct vrouter {
    unsigned int vr_num_if;
    unsigned char vr_vrrp_mac[VR_ETHER_ALEN];
    unsigned char vr_mac[VR_ETHER_ALEN];
    unsigned int vr_ip;

    unsigned int vr_max_interfaces;
    struct vr_interface **vr_interfaces;
    unsigned int vr_max_nexthops;
    struct vr_nexthop **vr_nexthops;
    struct vr_rtable *vr_inet_rtable;
    struct vr_rtable *vr_inet6_rtable;
    struct vr_rtable *vr_inet_mcast_rtable;
    struct vr_rtable *vr_bridge_rtable;

    struct vr_btable *vr_flow_table;
    struct vr_btable *vr_oflow_table;
    struct vr_flow_table_info *vr_flow_table_info;
    unsigned int vr_flow_table_info_size;

    unsigned int vr_max_labels;
    struct vr_nexthop **vr_ilm;

    unsigned int vr_max_mirror_indices;
    struct vr_mirror_entry **vr_mirrors;
    vr_itable_t vr_mirror_md;
    vr_itable_t vr_vxlan_table;

    struct vr_btable *vr_fragment_table;
    struct vr_btable *vr_fragment_otable;
    struct vr_timer *vr_fragment_table_scanner;
    struct vr_timer *vr_fragment_otable_scanner;

    uint64_t **vr_pdrop_stats;

    uint16_t vr_link_local_ports_size;
    unsigned char *vr_link_local_ports;

    struct vr_interface *vr_agent_if;
    struct vr_interface *vr_host_if;
    struct vr_interface *vr_eth_if;
};

struct vr_defer_data {
    void *vdd_data;
};

extern volatile bool vr_not_ready;

extern struct host_os *vrouter_host;

extern struct vrouter *vrouter_get(unsigned int);
extern int vrouter_init(void);
extern int vr_module_error(int, const char *, int, int);
extern int vhost_init(void);

#ifdef __cplusplus
}
#endif

#endif /* __VROUTER_H__ */
