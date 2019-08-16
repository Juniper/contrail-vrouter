import socket

SANDESH_OPER_ADD                   = 0
SANDESH_OPER_GET                   = 1
SANDESH_OPER_DEL                   = 2

VIF_TYPE_HOST                      = 0
VIF_TYPE_AGENT                     = 1
VIF_TYPE_PHYSICAL                  = 2
VIF_TYPE_VIRTUAL                   = 3
VIF_TYPE_XEN_LL_HOST               = 4
VIF_TYPE_GATEWAY                   = 5
VIF_TYPE_VIRTUAL_VLAN              = 6
VIF_TYPE_STATS                     = 7
VIF_TYPE_VLAN                      = 8
VIF_TYPE_MONITORING                = 9
VIF_TYPE_MAX                       = 10

VR_INTERFACE_NAME_LEN              = 64
VIF_MAX_MIRROR_MD_SIZE             = 255

VIF_SRC_MACS                       = 4

VIF_TRANSPORT_VIRTUAL              = 0
VIF_TRANSPORT_ETH                  = 1
VIF_TRANSPORT_PMD                  = 2
VIF_TRANSPORT_SOCKET               = 3

VR_IF_ADD                          = 0
VR_IF_DEL                          = 1

VIF_FLAG_POLICY_ENABLED            = 0x1
VIF_FLAG_XCONNECT                  = 0x2
VIF_FLAG_SERVICE_IF                = 0x4
VIF_FLAG_MIRROR_RX                 = 0x8
VIF_FLAG_MIRROR_TX                 = 0x10
VIF_FLAG_TX_CSUM_OFFLOAD           = 0x20
VIF_FLAG_L3_ENABLED                = 0x40
VIF_FLAG_L2_ENABLED                = 0x80
VIF_FLAG_DHCP_ENABLED              = 0x100
VIF_FLAG_VHOST_PHYS                = 0x200
VIF_FLAG_PROMISCOUS                = 0x400
VIF_FLAG_NATIVE_VLAN_TAG           = 0x800
VIF_FLAG_NO_ARP_PROXY              = 0x1000
VIF_FLAG_PMD                       = 0x2000
VIF_FLAG_FILTERING_OFFLOAD         = 0x4000
VIF_FLAG_MONITORED                 = 0x8000
VIF_FLAG_UNKNOWN_UC_FLOOD          = 0x10000
VIF_FLAG_VLAN_OFFLOAD              = 0x20000
VIF_FLAG_DROP_NEW_FLOWS            = 0x40000
VIF_FLAG_MAC_LEARN                 = 0x80000
VIF_FLAG_MAC_PROXY                 = 0x100000
VIF_FLAG_ETREE_ROOT                = 0x200000
VIF_FLAG_GRO_NEEDED                = 0x400000
VIF_FLAG_MRG_RXBUF                 = 0x800000
VIF_FLAG_MIRROR_NOTAG              = 0x1000000
VIF_FLAG_IGMP_ENABLED              = 0x2000000
VIF_FLAG_MOCK_PHYSICAL             = 0x4000000
VIF_FLAG_GET_DROP_STATS            = 0x01

VIF_VRF_TABLE_ENTRIES              = 1024
VIF_VRF_INVALID                    = 65535

VIF_ENCAP_TYPE_ETHER               = 1
VIF_ENCAP_TYPE_L3                  = 2
VIF_ENCAP_TYPE_L3_DECRYPT          = 3

VR_DEF_NEXTHOPS                    = 65536
NH_TABLE_ENTRIES                   = VR_DEF_NEXTHOPS
VR_NEXTHOP_COMPONENT_DUMP_LIMIT    = 16
NH_DISCARD_ID                      = 0

NH_TYPE_DEAD                            = 0
NH_TYPE_RCV                             = 1
NH_TYPE_ENCAP                           = 2
NH_TYPE_TUNNEL                          = 3
NH_TYPE_RESOLVE                         = 4
NH_TYPE_DISCARD                         = 5
NH_TYPE_COMPOSITE                       = 6
NH_TYPE_VRF_TRANSLATE                   = 7
NH_TYPE_L2_RCV                          = 8
NH_TYPE_MAX                             = 9

NH_VXLAN_VRF                       = NH_TYPE_VRF_TRANSLATE

NH_FLAG_VALID                      = 0x000001
NH_FLAG_POLICY_ENABLED             = 0x000002
# 0x000004 is free
NH_FLAG_TUNNEL_GRE                 = 0x000008
NH_FLAG_TUNNEL_UDP                 = 0x000010
NH_FLAG_MCAST                      = 0x000020
NH_FLAG_TUNNEL_UDP_MPLS            = 0x000040
NH_FLAG_TUNNEL_VXLAN               = 0x000080
NH_FLAG_RELAXED_POLICY             = 0x000100
NH_FLAG_COMPOSITE_FABRIC           = 0x000200
NH_FLAG_COMPOSITE_ECMP             = 0x000400
NH_FLAG_COMPOSITE_LU_ECMP          = 0x000800
NH_FLAG_COMPOSITE_EVPN             = 0x001000
NH_FLAG_COMPOSITE_ENCAP            = 0x002000
NH_FLAG_COMPOSITE_TOR              = 0x004000
NH_FLAG_ROUTE_LOOKUP               = 0x008000
NH_FLAG_UNKNOWN_UC_FLOOD           = 0x010000
NH_FLAG_TUNNEL_SIP_COPY            = 0x020000
NH_FLAG_FLOW_LOOKUP                = 0x040000
NH_FLAG_TUNNEL_PBB                 = 0x080000
NH_FLAG_MAC_LEARN                  = 0x100000
NH_FLAG_ETREE_ROOT                 = 0x200000
NH_FLAG_INDIRECT                   = 0x400000
NH_FLAG_L2_CONTROL_DATA            = 0x800000
NH_FLAG_CRYPT_TRAFFIC              = 0x01000000
NH_FLAG_L3_VXLAN                   = 0x02000000
NH_FLAG_TUNNEL_MPLS_O_MPLS         = 0x04000000
NH_FLAG_VALIDATE_MCAST_SRC         = 0x08000000

NH_SOURCE_INVALID                  = 0
NH_SOURCE_VALID                    = 1
NH_SOURCE_MISMATCH                 = 2

NH_ECMP_CONFIG_HASH_BITS           = 5
NH_ECMP_CONFIG_HASH_MASK           = ((1 << NH_ECMP_CONFIG_HASH_BITS) - 1)
NH_ECMP_CONFIG_HASH_PROTO          = 0x01
NH_ECMP_CONFIG_HASH_SRC_IP         = 0x02
NH_ECMP_CONFIG_HASH_SRC_PORT       = 0x04
NH_ECMP_CONFIG_HASH_DST_IP         = 0x08
NH_ECMP_CONFIG_HASH_DST_PORT       = 0x10

AF_UNIX                            = 1
AF_INET                            = 2
AF_BRIDGE                          = 7
AF_INET6                           = 10

VR_RT_LABEL_VALID_FLAG             = 0x1
VR_RT_ARP_PROXY_FLAG               = 0x2
VR_RT_ARP_TRAP_FLAG                = 0x4
VR_RT_ARP_FLOOD_FLAG               = 0x8

VR_BE_VALID_FLAG                   = 0x01
VR_BE_LABEL_VALID_FLAG             = 0x02
VR_BE_FLOOD_DHCP_FLAG              = 0x04
VR_BE_MAC_MOVED_FLAG               = 0x08
VR_BE_L2_CONTROL_DATA_FLAG         = 0x10
VR_BE_MAC_NEW_FLAG                 = 0x20
VR_BE_EVPN_CONTROL_PROCESSING_FLAG = 0x40

VRF_FLAG_VALID                     = 0x0001
VRF_FLAG_HBF_L_VALID               = 0x0002
VRF_FLAG_HBF_R_VALID               = 0x0004

FLOW_OPER_SET                      = 0
FLOW_OPER_LIST                     = 1
FLOW_OPER_TABLE_GET                = 2

VR_FLOW_ACTION_DROP                = 0x0
VR_FLOW_ACTION_HOLD                = 0x1
VR_FLOW_ACTION_FORWARD             = 0x2
VR_FLOW_ACTION_NAT                 = 0x3

FLOW_HELD                          = 0
FLOW_FORWARD                       = 1
FLOW_DROP                          = 2
FLOW_TRAP                          = 3
FLOW_CONSUMED                      = 4
FLOW_EVICT_DROP                    = 5

VR_FLOW_RESP_FLAG_DELETED          = 0x0001

VR_FLOW_FLAG_ACTIVE                = 0x0001
VR_FLOW_FLAG_MODIFIED              = 0x0100
VR_FLOW_FLAG_NEW_FLOW              = 0x0200
VR_FLOW_FLAG_EVICT_CANDIDATE       = 0x0400
VR_FLOW_FLAG_EVICTED               = 0x0800
VR_RFLOW_VALID                     = 0x1000
VR_FLOW_FLAG_MIRROR                = 0x2000
VR_FLOW_FLAG_VRFT                  = 0x4000
VR_FLOW_FLAG_LINK_LOCAL            = 0x8000

# for NAT
VR_FLOW_FLAG_SNAT                  = 0x2
VR_FLOW_FLAG_SPAT                  = 0x4
VR_FLOW_FLAG_DNAT                  = 0x8
VR_FLOW_FLAG_DPAT                  = 0x10
VR_FLOW_FLAG_NAT_MASK              = VR_FLOW_FLAG_SNAT | \
                                     VR_FLOW_FLAG_SPAT | \
                                     VR_FLOW_FLAG_DNAT | \
                                     VR_FLOW_FLAG_DPAT

# for TRAP
VR_FLOW_FLAG_TRAP_ECMP             = 0x20
VR_FLOW_FLAG_TRAP_MASK             = VR_FLOW_FLAG_TRAP_ECMP
VR_FLOW_FLAG_DELETE_MARKED         = 0x40
VR_FLOW_BGP_SERVICE                = 0x80

VR_FLOW_EXT_FLAG_FORCE_EVICT       = 0x0001
# Mock src UDP port used to set constant port value for vtest
VR_FLOW_EXT_FLAG_MOCK_SRC_UDP      = 0x0002
VR_FLOW_MOCK_SRC_UDP_PORT          = 0x12b5

# Flow Action Reason code
VR_FLOW_DR_UNKNOWN                 = 0x00
VR_FLOW_DR_UNAVIALABLE_INTF        = 0x01
VR_FLOW_DR_IPv4_FWD_DIS            = 0x02
VR_FLOW_DR_UNAVAILABLE_VRF         = 0x03
VR_FLOW_DR_NO_SRC_ROUTE            = 0x04
VR_FLOW_DR_NO_DST_ROUTE            = 0x05
VR_FLOW_DR_AUDIT_ENTRY             = 0x06
VR_FLOW_DR_VRF_CHANGE              = 0x07
VR_FLOW_DR_NO_REVERSE_FLOW         = 0x08
VR_FLOW_DR_REVERSE_FLOW_CHANGE     = 0x09
VR_FLOW_DR_NAT_CHANGE              = 0x0a
VR_FLOW_DR_FLOW_LIMIT              = 0x0b
VR_FLOW_DR_LINKLOCAL_SRC_NAT       = 0x0c
VR_FLOW_DR_FAILED_VROUTER_INSTALL  = 0x0d
VR_FLOW_DR_INVALID_L2_FLOW         = 0x0e
VR_FLOW_DR_FLOW_ON_TSN             = 0x0f
VR_FLOW_DR_NO_MIRROR_ENTRY         = 0x10
VR_FLOW_DR_SAME_FLOW_RFLOW_KEY     = 0x11
VR_FLOW_DR_PORT_MAP_DROP           = 0x12
VR_FLOW_DR_NO_SRC_ROUTE_L2RPF      = 0x13
VR_FLOW_DR_FAT_FLOW_NAT_CONFLICT   = 0x14
VR_FLOW_DR_POLICY                  = 0x15
VR_FLOW_DR_OUT_POLICY              = 0x16
VR_FLOW_DR_SG                      = 0x17
VR_FLOW_DR_OUT_SG                  = 0x18
VR_FLOW_DR_REVERSE_SG              = 0x19
VR_FLOW_DR_REVERSE_OUT_SG          = 0x1a
VR_FLOW_DR_FW_POLICY               = 0x1b
VR_FLOW_DR_OUT_FW_POLICY           = 0x1c
VR_FLOW_DR_REVERSE_FW_POLICY       = 0x1d
VR_FLOW_DR_REVERSE_OUT_FW_POLICY   = 0x1e
VR_FLOW_DR_FWAAS_POLICY            = 0x1f
VR_FLOW_DR_OUT_FWAAS_POLICY        = 0x20
VR_FLOW_DR_REVERSE_FWAAS_POLICY    = 0x21
VR_FLOW_DR_REVERSE_OUT_FWAAS_POLICY = 0x22

VR_IP6_ADDRESS_LEN                 = 16

VR_FLOW_KEY_ALL                    = 0x1F
VR_FLOW_KEY_NONE                   = 0x00
VR_FLOW_KEY_PROTO                  = 0x01
VR_FLOW_KEY_SRC_IP                 = 0x02
VR_FLOW_KEY_SRC_PORT               = 0x04
VR_FLOW_KEY_DST_IP                 = 0x08
VR_FLOW_KEY_DST_PORT               = 0x10

VR_LL_RP_TCP_INDEX                 = 0x0
VR_LL_RP_UDP_INDEX                 = 0x1
VR_LL_RP_ICMP_INDEX                = 0x2
VR_LL_RP_MAX                       = 0x3

# ethernet header
VR_ETHER_DMAC_OFF                  = 0
VR_ETHER_SMAC_OFF                  = 6
VR_ETHER_PROTO_OFF                 = 12
VR_ETHER_VLAN_PROTO_OFF            = 16
VR_ETHER_PROTO_MAC_OFF             = 1
VR_ETHER_PROTO_MAC_LEN             = 2
VR_IP_PROTO_ICMP                   = 1
VR_IP_PROTO_IGMP                   = 2
VR_IP_PROTO_TCP                    = 6
VR_IP_PROTO_UDP                    = 17
VR_IP_PROTO_GRE                    = 47
VR_IP_PROTO_ICMP6                  = 58
VR_IP_PROTO_SCTP                   = 132
VR_GRE_FLAG_CSUM                   = (socket.ntohs(0x8000))
VR_GRE_FLAG_KEY                    = (socket.ntohs(0x2000))
VR_DHCP_SRC_PORT                   = 68
VR_DHCP6_SRC_PORT                  = 546

# Size of basic GRE header
VR_GRE_BASIC_HDR_LEN               = 4

# Size of GRE header with checksum
VR_GRE_CKSUM_HDR_LEN               = 8

# Size of GRE header with key
VR_GRE_KEY_HDR_LEN                 = 8

VR_DYNAMIC_PORT_START              = 0
VR_DYNAMIC_PORT_END                = 65535

VROUTER_OVERLAY_LEN                = 40
VROUTER_L2_OVERLAY_LEN             = 62

# packets originated by DP. For eg: mirrored packets
VP_FLAG_FROM_DP                   = (1 << 0)
VP_FLAG_TO_ME                     = (1 << 1)
# request policy lookup for components other than interfaces
VP_FLAG_FLOW_GET                  = (1 << 2)
# packet already went through one round of policy lookup
VP_FLAG_FLOW_SET                  = (1 << 3)
VP_FLAG_MULTICAST                 = (1 << 4)
# Partially checksummed by VM
VP_FLAG_CSUM_PARTIAL              = (1 << 5)
# Attempt to do receive offload on inner packet
VP_FLAG_GRO                       = (1 << 6)
# Attempt to do segmentation on inner packet
VP_FLAG_GSO                       = (1 << 7)
# Diagnostic packet
VP_FLAG_DIAG                      = (1 << 8)
VP_FLAG_GROED                     = (1 << 9)

# possible 256 values of what a packet can be. currently, this value is
# used only as an aid in fragmentation.

VP_TYPE_NULL                      = 0
VP_TYPE_ARP                       = 1
VP_TYPE_IP                        = 2
VP_TYPE_IP6                       = 3
VP_TYPE_IPOIP                     = 4
VP_TYPE_IP6OIP                    = 5
VP_TYPE_AGENT                     = 6
VP_TYPE_PBB                       = 7
VP_TYPE_UNKNOWN                   = 8
VP_TYPE_MAX                       = VP_TYPE_UNKNOWN

# Values to define how to proceed with handling a packet.
PKT_RET_FAST_PATH                 = 1
PKT_RET_SLOW_PATH                 = 2
PKT_RET_ERROR                     = 3
PKT_RET_UNHANDLED                 = 4

# Values to define the MPLS tunnel type
PKT_MPLS_TUNNEL_INVALID           = 0x00
PKT_MPLS_TUNNEL_L3                = 0x01
PKT_MPLS_TUNNEL_L2_UCAST          = 0x02
PKT_MPLS_TUNNEL_L2_MCAST          = 0x03
PKT_MPLS_TUNNEL_L2_CONTROL_DATA   = 0x04

# Values to defaine the srouce of Multicast packet
PKT_SRC_TOR_REPL_TREE             = 0x1
PKT_SRC_INGRESS_REPL_TREE         = 0x2
PKT_SRC_EDGE_REPL_TREE            = 0x4

# Values to define the encap type of outgoing packet
PKT_ENCAP_MPLS                    = 0x01
PKT_ENCAP_VXLAN                   = 0x02

# packet drop reasons
VP_DROP_DISCARD                   = 0
VP_DROP_PULL                      = 1
VP_DROP_INVALID_IF                = 2
VP_DROP_INVALID_ARP               = 3
VP_DROP_TRAP_NO_IF                = 4
VP_DROP_NOWHERE_TO_GO             = 5
VP_DROP_FLOW_QUEUE_LIMIT_EXCEEDED = 6
VP_DROP_FLOW_NO_MEMORY            = 7
VP_DROP_FLOW_INVALID_PROTOCOL     = 8
VP_DROP_FLOW_NAT_NO_RFLOW         = 9
VP_DROP_FLOW_ACTION_DROP          = 10
VP_DROP_FLOW_ACTION_INVALID       = 11
VP_DROP_FLOW_UNUSABLE             = 12
VP_DROP_FLOW_TABLE_FULL           = 13
VP_DROP_INTERFACE_TX_DISCARD      = 14
VP_DROP_INTERFACE_DROP            = 15
VP_DROP_DUPLICATED                = 16
VP_DROP_PUSH                      = 17
VP_DROP_TTL_EXCEEDED              = 18
VP_DROP_INVALID_NH                = 19
VP_DROP_INVALID_LABEL             = 20
VP_DROP_INVALID_PROTOCOL          = 21
VP_DROP_INTERFACE_RX_DISCARD      = 22
VP_DROP_INVALID_MCAST_SOURCE      = 23
VP_DROP_HEAD_ALLOC_FAIL           = 24
VP_DROP_PCOW_FAIL                 = 25
VP_DROP_MCAST_DF_BIT              = 26
VP_DROP_MCAST_CLONE_FAIL          = 27
VP_DROP_NO_MEMORY                 = 28
VP_DROP_REWRITE_FAIL              = 29
VP_DROP_MISC                      = 30
VP_DROP_INVALID_PACKET            = 31
VP_DROP_CKSUM_ERR                 = 32
VP_DROP_NO_FMD                    = 33
VP_DROP_CLONED_ORIGINAL           = 34
VP_DROP_INVALID_VNID              = 35
VP_DROP_FRAGMENTS                 = 36
VP_DROP_INVALID_SOURCE            = 37
VP_DROP_L2_NO_ROUTE               = 38
VP_DROP_FRAGMENT_QUEUE_FAIL       = 39
VP_DROP_VLAN_FWD_TX               = 40
VP_DROP_VLAN_FWD_ENQ              = 41
VP_DROP_NEW_FLOWS                 = 42
VP_DROP_FLOW_EVICT                = 43
VP_DROP_TRAP_ORIGINAL             = 44
VP_DROP_LEAF_TO_LEAF              = 45
VP_DROP_BMAC_ISID_MISMATCH        = 46
VP_DROP_PKT_LOOP                  = 47
VP_DROP_NO_CRYPT_PATH             = 48
VP_DROP_MAX                       = 49

VP_QUEUE_INVALID                  = 0xFF
VP_PRIORITY_INVALID               = 0xF

VLAN_ID_INVALID                   = 0xFFFF
VLAN_ID_MAX                       = 0xFFFF
VR_VLAN_PRIORITY_SHIFT            = 13

VR_ARP_HW_LEN                     = 6
VR_ARP_OP_REQUEST                 = 1
VR_ARP_OP_REPLY                   = 2

VR_ETH_PROTO_ARP                  = 0x806
VR_ETH_PROTO_IP                   = 0x800
VR_ETH_PROTO_IP6                  = 0x86DD
VR_ETH_PROTO_VLAN                 = 0x8100
VR_ETH_PROTO_PBB                  = 0x88E7

VR_DIAG_CSUM                      = 0xFFFF
VR_UDP_PORT_RANGE_START           = 49152
VR_UDP_PORT_RANGE_END             = 65535

VR_ARP_HW_TYPE_ETHER              = 1
VR_ARP_PROTO_LEN_IPV4             = 4

VR_IP_DF                          = (0x1 << 14)
VR_IP_MF                          = (0x1 << 13)
VR_IP_FRAG_OFFSET_MASK            = (VR_IP_MF - 1)

VR_IP_ADDRESS_LEN                 = 4

VR_IP6_MF                         = 0x1
VR_IP6_FRAG_OFFSET_BITS           = 3

MCAST_IP                          = (0xE0000000)
MCAST_IP_MASK                     = (0xF0000000)

VR_TCP_FLAG_FIN                   = 0x0001
VR_TCP_FLAG_SYN                   = 0x0002
VR_TCP_FLAG_RST                   = 0x0004
VR_TCP_FLAG_PSH                   = 0x0008
VR_TCP_FLAG_ACK                   = 0x0010
VR_TCP_FLAG_URG                   = 0x0020
VR_TCP_FLAG_ECN                   = 0x0040
VR_TCP_FLAG_CWR                   = 0x0080

VR_TCP_OPT_EOL                    = 0
VR_TCP_OPT_NOP                    = 1
VR_TCP_OPT_MSS                    = 2

VR_TCP_OLEN_MSS                   = 4

VR_ICMP_TYPE_ECHO_REPLY           = 0
VR_ICMP_TYPE_DEST_UNREACH         = 3
VR_ICMP_TYPE_ECHO                 = 8
VR_ICMP_TYPE_TIME_EXCEEDED        = 11

VR_ICMP6_TYPE_PKT_TOO_BIG         = 2
VR_ICMP6_TYPE_ECHO_REQ            = 128
VR_ICMP6_TYPE_ECHO_REPLY          = 129
VR_ICMP6_TYPE_ROUTER_SOL          = 133
VR_ICMP6_TYPE_NEIGH_SOL           = 135
VR_ICMP6_TYPE_NEIGH_AD            = 136

VR_ICMP6_NEIGH_AD_FLAG_ROUTER     = 0x8000
VR_ICMP6_NEIGH_AD_FLAG_SOLCITED   = 0x4000
VR_ICMP6_NEIGH_AD_FLAG_OVERRIDE   = 0x2000

VR_ICMP6_NEIGH_AD_FLAG_ROUTER     = 0x8000
VR_ICMP6_NEIGH_AD_FLAG_SOLCITED   = 0x4000
VR_ICMP6_NEIGH_AD_FLAG_OVERRIDE   = 0x2000

VR_IP6_PROTO_FRAG                 = 44

VR_VXLAN_IBIT                     = 0x08000000
VR_VXLAN_RABIT                    = 0x01000000

VR_L2_CTRL_DATA                   = (0x0000)
VR_L2_CTRL_DATA_LEN               = 4

FMD_FLAG_LABEL_IS_VXLAN_ID        = 0x01
FMD_FLAG_MAC_IS_MY_MAC            = 0x02
FMD_FLAG_ETREE_ENABLE             = 0x04
FMD_FLAG_ETREE_ROOT               = 0x08
FMD_FLAG_L2_CONTROL_DATA          = 0x10
FMD_PKT_LOOP_TTL                  = 4
FMD_MIRROR_INVALID_DATA           = 0xFFFF
