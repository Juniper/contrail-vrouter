/*
 * vr_pkt_droplog.h
 *
 * Copyright (c) 2018 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_PKT_DROPLOG_H__
#define __VR_PKT_DROPLOG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "vr_defs.h"
#include "vr_qos.h"
#include "vr_flow.h"
#include "vrouter.h"
#include "vr_btable.h"
#include "vr_bridge.h"
#include "vr_mirror.h"
#include "vr_os.h"

/* All *.c *.h files inside vrouter folder are listed here */

/* Value 0 is invalid, while displaying the filenames and drop reason at utils side */
#define FILE_MAP(X) \
    X(INVALID) \
    X(UVROUTER_C) \
    X(VR_HOST_MTRANSPORT_C) \
    X(VR_HOST_MESSAGE_C) \
    X(ULINUX_C) \
    X(VR_HOST_INTERFACE_C) \
    X(VROUTER_HOST_MOD_C) \
    X(VR_HOST_PACKET_C) \
    X(VR_HOST_IO_C) \
    X(WIN_PFREE_C) \
    X(VR_HOST_C) \
    X(WIN_PCLONE_C) \
    X(WIN_PACKET_C) \
    X(WINDOWS_RANDOM_C) \
    X(WIN_MEMORY_C) \
    X(VR_PKT0_C) \
    X(VR_FRAGMENT_ASSEMBLER_C) \
    X(PRECOMPSRC2_C) \
    X(VR_DEVICES_C) \
    X(VR_DRIVER_C) \
    X(VR_WIN_TRANSPORT_C) \
    X(VR_SHMEM_DEVICES_C) \
    X(VR_NBL_C) \
    X(VR_KSYNC_C) \
    X(WIN_PACKET_RAW_C) \
    X(VR_OID_C) \
    X(VR_SHMEM_C) \
    X(VHOST_DEV_C) \
    X(VR_SOCKET_C) \
    X(VROUTER_MOD_C) \
    X(VR_BSD_TRANSPORT_C) \
    X(VR_MEM_C) \
    X(VR_DPDK_GSO_C) \
    X(DPDK_VROUTER_C) \
    X(VR_DPDK_VIRTIO_C) \
    X(VR_UVHOST_CLIENT_C) \
    X(VR_UVHOST_C) \
    X(VR_DPDK_KNIDEV_C) \
    X(VR_DPDK_ETHDEV_C) \
    X(VR_DPDK_FRAGMENT_ASSEMBLER_C) \
    X(VR_DPDK_HOST_C) \
    X(VR_DPDK_FILESTORE_C) \
    X(VR_DPDK_INTERFACE_C) \
    X(VR_DPDK_NETLINK_C) \
    X(VR_UVHOST_MSG_C) \
    X(VR_DPDK_GRO_C) \
    X(VR_DPDK_RINGDEV_C) \
    X(VR_UVHOST_UTIL_C) \
    X(VR_DPDK_PACKET_C) \
    X(VR_DPDK_TABLE_MEM_C) \
    X(VR_DPDK_TAPDEV_C) \
    X(VR_DPDK_USOCKET_C) \
    X(VR_DPDK_LCORE_C) \
    X(COMMON_TEST_C) \
    X(FAKE_WIN_PACKET_RAW_C) \
    X(TEST_WIN_PACKET_FREE_C) \
    X(FAKE_WIN_MEMORY_C) \
    X(ATOMIC_TEST_C) \
    X(RACES_TESTS_C) \
    X(FAKE_VROUTER_C) \
    X(TEST_WIN_PACKET_SPLIT_MULTI_PACKET_C) \
    X(TEST_WIN_PFREE_C) \
    X(TEST_WIN_PACKET_CLONE_C) \
    X(TEST_WIN_PCLONE_C) \
    X(DP_CORE_TEST_C) \
    X(VROUTER_C) \
    X(VR_MPLS_C) \
    X(VR_VIF_BRIDGE_C) \
    X(VR_SANDESH_C) \
    X(VR_ROUTE_C) \
    X(VR_STATS_C) \
    X(VR_IP_MTRIE_C) \
    X(VR_MESSAGE_C) \
    X(VR_INTERFACE_C) \
    X(VR_QOS_C) \
    X(VR_QUEUE_C) \
    X(VR_BRIDGE_C) \
    X(VR_BTABLE_C) \
    X(VR_PACKET_C) \
    X(VR_VRF_ASSIGN_C) \
    X(VR_FLOW_C) \
    X(VR_VXLAN_C) \
    X(VR_BUILDINFO_C) \
    X(VR_RESPONSE_C) \
    X(VR_NEXTHOP_C) \
    X(VR_MIRROR_C) \
    X(VR_FRAGMENT_C) \
    X(VR_PROTO_IP_C) \
    X(VR_BITMAP_C) \
    X(VR_INDEX_TABLE_C) \
    X(VR_DATAPATH_C) \
    X(VR_PROTO_IP6_C) \
    X(VR_HTABLE_C) \
    X(VR_GENETLINK_C) \
    X(SH_MEM_C) \
    X(CLIENT_C) \
    X(VHOST_CLIENT_C) \
    X(VIRT_QUEUE_C) \
    X(EXAMPLE_C) \
    X(VT_SANDESH_RESPONSE_C) \
    X(VT_PACKET_C) \
    X(VT_GEN_LIB_C) \
    X(VT_MAIN_C) \
    X(VT_PROCESS_XML_C) \
    X(SANDESH_GEN_C) \
    X(VT_MESSAGE_C) \
    X(FLOW_C) \
    X(QOSMAP_C) \
    X(VRMEMSTATS_C) \
    X(VIF_C) \
    X(DROPSTATS_C) \
    X(MIRROR_C) \
    X(WINDOWS_UTIL_C) \
    X(NL_UTIL_C) \
    X(UDP_UTIL_C) \
    X(INI_PARSER_C) \
    X(MPLS_C) \
    X(NH_C) \
    X(VXLAN_C) \
    X(VR_UTIL_C) \
    X(UNIX_UTIL_C) \
    X(VRFSTATS_C) \
    X(RT_C) \
    X(WIN_PACKET_RAW_H) \
    X(WIN_PACKET_H) \
    X(WINDOWS_TYPES_H) \
    X(WIN_PACKET_IMPL_H) \
    X(PRECOMP_H) \
    X(WINDOWS_NBL_H) \
    X(VR_WINDOWS_H) \
    X(WIN_ASSERT_H) \
    X(WINDOWS_SHMEM_H) \
    X(WIN_MEMORY_H) \
    X(WINDOWS_KSYNC_H) \
    X(WINDOWS_DEVICES_H) \
    X(WINDOWS_SHMEM_IOCTL_H) \
    X(WINDOWS_BUILTINS_H) \
    X(VR_DPDK_FILESTORE_H) \
    X(QEMU_UVHOST_H) \
    X(VR_UVHOST_UTIL_H) \
    X(VR_DPDK_NETLINK_H) \
    X(VR_DPDK_LCORE_H) \
    X(VR_UVHOST_MSG_H) \
    X(VR_DPDK_VIRTIO_H) \
    X(VR_DPDK_GRO_H) \
    X(VR_UVHOST_CLIENT_H) \
    X(VR_UVHOST_H) \
    X(VR_NEXTHOP_H) \
    X(VR_PROTO_H) \
    X(VR_RESPONSE_H) \
    X(VR_UTILS_H) \
    X(VR_OS_H) \
    X(GENETLINK_H) \
    X(VR_HASH_H) \
    X(VR_MIRROR_H) \
    X(VR_IP_MTRIE_H) \
    X(INI_PARSER_H) \
    X(VR_STATS_H) \
    X(VR_DEFS_H) \
    X(VR_HOST_INTERFACE_H) \
    X(VR_HOST_H) \
    X(VR_HOST_PACKET_H) \
    X(VR_FREEBSD_H) \
    X(VR_BUILDINFO_H) \
    X(UDP_UTIL_H) \
    X(VHOST_H) \
    X(VR_BRIDGE_H) \
    X(VR_BTABLE_H) \
    X(VR_DATAPATH_H) \
    X(VR_INDEX_TABLE_H) \
    X(VR_DPDK_H) \
    X(VROUTER_H) \
    X(VR_GENETLINK_H) \
    X(VR_FLOW_H) \
    X(VR_MEM_H) \
    X(VR_VXLAN_H) \
    X(ULINUX_H) \
    X(VR_PACKET_H) \
    X(VR_QUEUE_H) \
    X(VR_COMPAT_H) \
    X(VR_TEST_H) \
    X(VR_HTABLE_H) \
    X(VR_ROUTE_H) \
    X(VR_FRAGMENT_H) \
    X(VR_DPDK_USOCKET_H) \
    X(NL_UTIL_H) \
    X(VR_INTERFACE_H) \
    X(VR_BITMAP_H) \
    X(VR_LINUX_H) \
    X(VR_MPLS_H) \
    X(VR_SANDESH_H) \
    X(VR_DPDK_COMPAT_H) \
    X(VR_QOS_H) \
    X(VR_MESSAGE_H) \
    X(NETLINK_H) \
    X(FAKE_WIN_PACKET_H) \
    X(NDIS_H) \
    X(SUB_SIGNED_H) \
    X(ALGEBRAIC_RACES_H) \
    X(AND_UNSIGNED_H) \
    X(OR_UNSIGNED_H) \
    X(ADD_UNSIGNED_H) \
    X(UNIT_TESTS_H) \
    X(RACES_TESTS_H) \
    X(SUB_UNSIGNED_H) \
    X(BOOL_CAS_H) \
    X(TEST_DEFINES_H) \
    X(COMMON_TEST_H) \
    X(VIRTIO_HDR_H) \
    X(VHOST_CLIENT_H) \
    X(UVHOST_H) \
    X(VIRT_QUEUE_H) \
    X(SH_MEM_H) \
    X(VHOST_NET_H_) \
    X(UTIL_H) \
    X(CLIENT_H) \
    X(VT_PACKET_H) \
    X(VT_MAIN_H) \
    X(VT_GEN_LIB_H) \
    X(VT_PROCESS_XML_H) \
    X(VTEST_H) \
    X(VT_MESSAGE_H)


#define DROP_RSN_MAP(X) \
    X(INVALID) \
    X(VP_DROP_DISCARD) \
    X(VP_DROP_PULL) \
    X(VP_DROP_INVALID_IF) \
    X(VP_DROP_INVALID_ARP) \
    X(VP_DROP_TRAP_NO_IF) \
    X(VP_DROP_NOWHERE_TO_GO) \
    X(VP_DROP_FLOW_QUEUE_LIMIT_EXCEEDED) \
    X(VP_DROP_FLOW_NO_MEMORY) \
    X(VP_DROP_FLOW_INVALID_PROTOCOL) \
    X(VP_DROP_FLOW_NAT_NO_RFLOW) \
    X(VP_DROP_FLOW_ACTION_DROP) \
    X(VP_DROP_FLOW_ACTION_INVALID) \
    X(VP_DROP_FLOW_UNUSABLE) \
    X(VP_DROP_FLOW_TABLE_FULL) \
    X(VP_DROP_INTERFACE_TX_DISCARD) \
    X(VP_DROP_INTERFACE_DROP) \
    X(VP_DROP_DUPLICATED) \
    X(VP_DROP_PUSH) \
    X(VP_DROP_TTL_EXCEEDED) \
    X(VP_DROP_INVALID_NH) \
    X(VP_DROP_INVALID_LABEL) \
    X(VP_DROP_INVALID_PROTOCOL) \
    X(VP_DROP_INTERFACE_RX_DISCARD) \
    X(VP_DROP_INVALID_MCAST_SOURCE) \
    X(VP_DROP_HEAD_ALLOC_FAIL) \
    X(VP_DROP_PCOW_FAIL) \
    X(VP_DROP_MCAST_DF_BIT) \
    X(VP_DROP_MCAST_CLONE_FAIL) \
    X(VP_DROP_NO_MEMORY) \
    X(VP_DROP_REWRITE_FAIL) \
    X(VP_DROP_MISC) \
    X(VP_DROP_INVALID_PACKET) \
    X(VP_DROP_CKSUM_ERR) \
    X(VP_DROP_NO_FMD) \
    X(VP_DROP_CLONED_ORIGINAL) \
    X(VP_DROP_INVALID_VNID) \
    X(VP_DROP_FRAGMENTS) \
    X(VP_DROP_INVALID_SOURCE) \
    X(VP_DROP_L2_NO_ROUTE) \
    X(VP_DROP_FRAGMENT_QUEUE_FAIL) \
    X(VP_DROP_VLAN_FWD_TX) \
    X(VP_DROP_VLAN_FWD_ENQ) \
    X(VP_DROP_NEW_FLOWS) \
    X(VP_DROP_FLOW_EVICT) \
    X(VP_DROP_TRAP_ORIGINAL) \
    X(VP_DROP_LEAF_TO_LEAF) \
    X(VP_DROP_BMAC_ISID_MISMATCH) \
    X(VP_DROP_PKT_LOOP) \
    X(VP_DROP_NO_CRYPT_PATH) \
    X(VP_DROP_MAX)

#define enum_t(X) X,
#define string(X) #X,

typedef enum {
    FILE_MAP(enum_t)
} map_t;

/* VR_PKT_DROP_STATS_LOG_MAX macro denotes the number of entry for Packet log buffer on each core*/
#define VR_PKT_DROP_LOG_MAX 200

/* Currently we couldn't transfer data more than 4KB through sandesh.
 * so with the below VR_PKT_DROPLOG_MAX_ALLOW_BUFSZ macro,
 * we are processing those much of entries in a single transfer.
 * Below values is arrived based on size of vr_pkt_drop_log_t.
 * Currently, size is less than 4KB, If we add new entries as part of vr_pkt_drop_log_t structure,
 * then we need to consider the below macro size
 * */
#define VR_PKT_DROPLOG_MAX_ALLOW_BUFSZ 20

#define PKT_LOG(U, W, X, Y, Z) if(vr_pkt_droplog_sysctl_en == 1) { \
vr_pkt_drop_log_func(U, W, X, Y, Z); \
}
extern unsigned int vr_pkt_droplog_bufsz;
extern unsigned int vr_pkt_droplog_buf_en;
extern unsigned int vr_pkt_droplog_sysctl_en;
extern unsigned int vr_pkt_droplog_min_sysctl_en;
unsigned int vr_pkt_drop_log_req_get_size(void *);
struct vr_drop_loc
{
    map_t file;
    unsigned int line;
};

typedef struct vr_pkt_drop_log {
    time_t timestamp;
    unsigned char   vp_type;
    unsigned short  drop_reason;
    unsigned short  vif_idx;
    unsigned int    nh_id;
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    }src;
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    }dst;
    unsigned short  sport;
    unsigned short  dport;
    struct vr_drop_loc drop_loc;

    unsigned short  pkt_len;
    unsigned char   pkt_header[100];
} vr_pkt_drop_log_t;

struct vr_pkt_drop_st {
    vr_pkt_drop_log_t **vr_pkt_drop_log;
    uint64_t *vr_pkt_drop_log_buffer_index;
};

#define PKT_LOG_FILL(X,Y) X=Y;

#ifdef __cplusplus
}
#endif

#endif /* __VR_PKT_DROPLOG_H__ */
