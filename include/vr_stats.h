/*
 * vr_stats.h
 *
 * Copyright (c) 2017 Juniper Networks, Inc. All rights reserved.
 */
#ifndef __VR_STATS_H__
#define __VR_STATS_H__

#ifdef __cplusplus
extern "C" {
#endif

//#include "vr_packet.h"
//#include "vrouter.h"

//#if (VR_DROP_STATS_LOG_BUFFER_INFRA == STD_ON)
/* All *.c *.h files inside vrouter folders are listed here
 * file is mapping is used for storing dropstats log buffer
 * *.c files starting from 1
 * *.h files starting from 500*/

#define UVROUTER_C 	 1
#define VR_HOST_MTRANSPORT_C 	 2
#define VR_HOST_MESSAGE_C 	 3
#define ULINUX_C 	 4
#define VR_HOST_INTERFACE_C 	 5
#define VROUTER_HOST_MOD_C 	 6
#define VR_HOST_PACKET_C 	 7
#define VR_HOST_IO_C 	 8
#define WIN_PFREE_C 	 9
#define VR_HOST_C 	 10
#define WIN_PCLONE_C 	 11
#define WIN_PACKET_C 	 12
#define WINDOWS_RANDOM_C 	 13
#define WIN_MEMORY_C 	 14
#define VR_PKT0_C 	 15
#define VR_FRAGMENT_ASSEMBLER_C 	 16
#define PRECOMPSRC2_C 	 18
#define VR_DEVICES_C 	 19
#define VR_DRIVER_C 	 20
#define VR_WIN_TRANSPORT_C 	 21
#define VR_SHMEM_DEVICES_C 	 22
#define VR_NBL_C 	 23
#define VR_KSYNC_C 	 24
#define WIN_PACKET_RAW_C 	 25
#define VR_OID_C 	 26
#define VR_SHMEM_C 	 27
#define VHOST_DEV_C 	 28
#define VR_SOCKET_C 	 29
#define VROUTER_MOD_C 	 30
#define VR_BSD_TRANSPORT_C 	 31
#define VR_MEM_C 	 33
#define VR_DPDK_GSO_C 	 34
#define DPDK_VROUTER_C 	 35
#define VR_DPDK_VIRTIO_C 	 36
#define VR_UVHOST_CLIENT_C 	 37
#define VR_UVHOST_C 	 38
#define VR_DPDK_KNIDEV_C 	 39
#define VR_DPDK_ETHDEV_C 	 40
#define VR_DPDK_FRAGMENT_ASSEMBLER_C 	 41
#define VR_DPDK_HOST_C 	 42
#define VR_DPDK_FILESTORE_C 	 43
#define VR_DPDK_INTERFACE_C 	 44
#define VR_DPDK_NETLINK_C 	 45
#define VR_UVHOST_MSG_C 	 46
#define VR_DPDK_GRO_C 	 47
#define VR_DPDK_RINGDEV_C 	 48
#define VR_UVHOST_UTIL_C 	 49
#define VR_DPDK_PACKET_C 	 50
#define VR_DPDK_TABLE_MEM_C 	 51
#define VR_DPDK_TAPDEV_C 	 52
#define VR_DPDK_USOCKET_C 	 53
#define VR_DPDK_LCORE_C 	 54
#define COMMON_TEST_C 	 55
#define FAKE_WIN_PACKET_RAW_C 	 56
#define TEST_WIN_PACKET_FREE_C 	 57
#define FAKE_WIN_MEMORY_C 	 58
#define ATOMIC_TEST_C 	 59
#define RACES_TESTS_C 	 60
#define FAKE_VROUTER_C 	 61
#define TEST_WIN_PACKET_SPLIT_MULTI_PACKET_C 	 62
#define TEST_WIN_PFREE_C 	 63
#define TEST_WIN_PACKET_CLONE_C 	 64
#define TEST_WIN_PCLONE_C 	 65
#define DP_CORE_TEST_C 	 66
#define VROUTER_C 	 67
#define VR_MPLS_C 	 68
#define VR_VIF_BRIDGE_C 	 69
#define VR_SANDESH_C 	 70
#define VR_ROUTE_C 	 71
#define VR_STATS_C 	 72
#define VR_IP_MTRIE_C 	 73
#define VR_MESSAGE_C 	 74
#define VR_INTERFACE_C 	 75
#define VR_QOS_C 	 76
#define VR_QUEUE_C 	 77
#define VR_BRIDGE_C 	 78
#define VR_BTABLE_C 	 79
#define VR_PACKET_C 	 80
#define VR_VRF_ASSIGN_C 	 81
#define VR_FLOW_C 	 82
#define VR_VXLAN_C 	 83
#define VR_BUILDINFO_C 	 84
#define VR_RESPONSE_C 	 85
#define VR_NEXTHOP_C 	 86
#define VR_MIRROR_C 	 87
#define VR_FRAGMENT_C 	 88
#define VR_PROTO_IP_C 	 89
#define VR_BITMAP_C 	 90
#define VR_INDEX_TABLE_C 	 91
#define VR_DATAPATH_C 	 92
#define VR_PROTO_IP6_C 	 93
#define VR_HTABLE_C 	 94
#define VR_GENETLINK_C 	 100
#define SH_MEM_C 	 102
#define CLIENT_C 	 103
#define VHOST_CLIENT_C 	 104
#define VIRT_QUEUE_C 	 105
#define EXAMPLE_C 	 106
#define VT_SANDESH_RESPONSE_C 	 107
#define VT_PACKET_C 	 108
#define VT_GEN_LIB_C 	 109
#define VT_MAIN_C 	 111
#define VT_PROCESS_XML_C 	 112
#define SANDESH_GEN_C 	 113
#define VT_MESSAGE_C 	 114
#define FLOW_C 	 115
#define QOSMAP_C 	 116
#define VRMEMSTATS_C 	 117
#define VIF_C 	 118
#define DROPSTATS_C 	 119
#define MIRROR_C 	 120
#define WINDOWS_UTIL_C 	 121
#define NL_UTIL_C 	 122
#define UDP_UTIL_C 	 123
#define INI_PARSER_C 	 124
#define MPLS_C 	 125
#define NH_C 	 126
#define VXLAN_C 	 127
#define VR_UTIL_C 	 128
#define UNIX_UTIL_C 	 129
#define VRFSTATS_C 	 130
#define RT_C 	 131



#define WIN_PACKET_RAW_H 	 500
#define WIN_PACKET_H 	 501
#define WINDOWS_TYPES_H 	 502
#define WIN_PACKET_IMPL_H 	 503
#define PRECOMP_H 	 504
#define WINDOWS_NBL_H 	 505
#define VR_WINDOWS_H 	 506
#define WIN_ASSERT_H 	 507
#define WINDOWS_SHMEM_H 	 508
#define WIN_MEMORY_H 	 509
#define WINDOWS_KSYNC_H 	 510
#define WINDOWS_DEVICES_H 	 511
#define WINDOWS_SHMEM_IOCTL_H 	 512
#define WINDOWS_BUILTINS_H 	 513
#define VR_DPDK_FILESTORE_H 	 514
#define QEMU_UVHOST_H 	 515
#define VR_UVHOST_UTIL_H 	 516
#define VR_DPDK_NETLINK_H 	 517
#define VR_DPDK_LCORE_H 	 518
#define VR_UVHOST_MSG_H 	 519
#define VR_DPDK_VIRTIO_H 	 520
#define VR_DPDK_GRO_H 	 521
#define VR_UVHOST_CLIENT_H 	 522
#define VR_UVHOST_H 	 523
#define VR_NEXTHOP_H 	 524
#define VR_PROTO_H 	 525
#define VR_RESPONSE_H 	 526
#define VR_UTILS_H 	 527
#define VR_OS_H 	 528
#define GENETLINK_H 	 529
#define VR_HASH_H 	 530
#define VR_MIRROR_H 	 531
#define VR_IP_MTRIE_H 	 532
#define INI_PARSER_H 	 533
#define VR_STATS_H 	 534
#define VR_DEFS_H 	 535
#define VR_HOST_INTERFACE_H 	 536
#define VR_HOST_H 	 537
#define VR_HOST_PACKET_H 	 538
#define VR_FREEBSD_H 	 539
#define VR_BUILDINFO_H 	 540
#define UDP_UTIL_H 	 541
#define VHOST_H 	 542
#define VR_BRIDGE_H 	 543
#define VR_BTABLE_H 	 544
#define VR_DATAPATH_H 	 545
#define VR_INDEX_TABLE_H 	 546
#define VR_DPDK_H 	 547
#define VROUTER_H 	 548
#define VR_GENETLINK_H 	 549
#define VR_FLOW_H 	 550
#define VR_MEM_H 	 551
#define VR_VXLAN_H 	 552
#define ULINUX_H 	 553
#define VR_PACKET_H 	 554
#define VR_QUEUE_H 	 555
#define VR_COMPAT_H 	 556
#define VR_TEST_H 	 557
#define VR_HTABLE_H 	 558
#define VR_ROUTE_H 	 559
#define VR_FRAGMENT_H 	 560
#define VR_DPDK_USOCKET_H 	 561
#define NL_UTIL_H 	 562
#define VR_INTERFACE_H 	 563
#define VR_BITMAP_H 	 564
#define VR_LINUX_H 	 565
#define VR_MPLS_H 	 566
#define VR_SANDESH_H 	 567
#define VR_DPDK_COMPAT_H 	 568
#define VR_QOS_H 	 569
#define VR_MESSAGE_H 	 570
#define NETLINK_H 	 571
#define FAKE_WIN_PACKET_H 	 572
#define NDIS_H 	 573
#define SUB_SIGNED_H 	 574
#define ALGEBRAIC_RACES_H 	 575
#define AND_UNSIGNED_H 	 576
#define OR_UNSIGNED_H 	 577
#define ADD_UNSIGNED_H 	 578
#define UNIT_TESTS_H 	 579
#define RACES_TESTS_H 	 580
#define SUB_UNSIGNED_H 	 581
#define BOOL_CAS_H 	 582
#define TEST_DEFINES_H 	 583
#define COMMON_TEST_H 	 584
#define VIRTIO_HDR_H 	 585
#define VHOST_CLIENT_H 	 586
#define UVHOST_H 	 587
#define VIRT_QUEUE_H 	 588
#define SH_MEM_H 	 589
#define VHOST_NET_H 	 590
#define UTIL_H 	 591
#define CLIENT_H 	 592
#define VT_PACKET_H 	 593
#define VT_MAIN_H 	 594
#define VT_GEN_LIB_H 	 595
#define VT_PROCESS_XML_H 	 596
#define VTEST_H 	 597
#define VT_MESSAGE_H 	 598

//#endif

extern void vr_malloc_stats(unsigned int, unsigned int);
extern void vr_free_stats(unsigned int);



#ifdef __cplusplus
}
#endif

#endif /* __VR_STATS_H__ */
