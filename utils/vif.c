/*
 * vif.c -- 'vrouter' interface utility
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <getopt.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>

#include "vr_os.h"

#include <sys/types.h>
#include <sys/socket.h>

#if defined(__linux__)
#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>


#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#elif defined(__FreeBSD__)
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#endif

#include "vr_types.h"
#include "vr_message.h"
#include "vr_packet.h"
#include "vr_interface.h"
#include "vhost.h"
#include "vr_genetlink.h"
#include "nl_util.h"
#include "ini_parser.h"


#define VHOST_TYPE_STRING           "vhost"
#define AGENT_TYPE_STRING           "agent"
#define PHYSICAL_TYPE_STRING        "physical"
#define VIRTUAL_TYPE_STRING         "virtual"
#define XEN_LL_TYPE_STRING          "xenll"
#define GATEWAY_TYPE_STRING         "gateway"
#define VIRTUAL_VLAN_TYPE_STRING    "virtual-vlan"
#define STATS_TYPE_STRING           "stats"
#define MONITORING_TYPE_STRING      "monitoring"

static struct nl_client *cl;
static char flag_string[32], if_name[IFNAMSIZ];
static int if_kindex = -1, vrf_id, vr_ifindex = -1;
static int if_pmdindex = -1, vif_index = -1;
static bool need_xconnect_if = false;
static bool need_vif_id = false;
static int if_xconnect_kindex = -1;
static short vlan_id = -1;
static int vr_ifflags;
static unsigned int core = (unsigned)-1;

static int add_set, create_set, get_set, list_set;
static int kindex_set, type_set, help_set, set_set, vlan_set, dhcp_set;
static int vrf_set, mac_set, delete_set, policy_set, pmd_set, vindex_set, pci_set;
static int xconnect_set, vif_set, vhost_phys_set, core_set, rate_set;

static unsigned int vr_op, vr_if_type;
static bool ignore_error = false, dump_pending = false;
static bool vr_vrf_assign_dump = false;
static int dump_marker = -1, var_marker = -1;

static int platform;

static int8_t vr_ifmac[6];
static struct ether_addr *mac_opt;

static vr_interface_req prev_req;
static struct timeval last_time;


static void Usage(void);
static void rate_stats_diff(vr_interface_req *);
static void rate_stats(struct nl_client *, unsigned int);

static struct vr_util_flags flag_metadata[] = {
    {VIF_FLAG_POLICY_ENABLED,   "P",    "Policy"            },
    {VIF_FLAG_XCONNECT,         "X",    "Cross Connect"     },
    {VIF_FLAG_SERVICE_IF,       "S",    "Service Chain"     },
    {VIF_FLAG_MIRROR_RX,        "Mr",   "Receive Mirror"    },
    {VIF_FLAG_MIRROR_TX,        "Mt",   "Transmit Mirror"   },
    {VIF_FLAG_TX_CSUM_OFFLOAD,  "Tc",   "Transmit Checksum Offload"},
    {VIF_FLAG_L3_ENABLED,       "L3",   "Layer 3"           },
    {VIF_FLAG_L2_ENABLED,       "L2",   "Layer 2"           },
    {VIF_FLAG_DHCP_ENABLED,     "D",    "DHCP"              },
    {VIF_FLAG_VHOST_PHYS,       "Vp",   "Vhost Physical"    },
    {VIF_FLAG_PROMISCOUS,       "Pr",   "Promiscuous"       },
    {VIF_FLAG_NATIVE_VLAN_TAG,  "Vnt",  "Native Vlan Tagged"},
    {VIF_FLAG_NO_ARP_PROXY,     "Mnp",  "No MAC Proxy"      },
    {VIF_FLAG_PMD,              "Dpdk", "DPDK PMD Interface"},
    {VIF_FLAG_FILTERING_OFFLOAD,"Rfl",  "Receive Filtering Offload"},
    {VIF_FLAG_MONITORED,        "Mon",  "Interface is Monitored"},
    {VIF_FLAG_UNKNOWN_UC_FLOOD, "Uuf",  "Unknown Unicast Flood"},
    {VIF_FLAG_VLAN_OFFLOAD,     "Vof",  "VLAN insert/strip offload"},
};

static char *
vr_get_if_type_string(int t)
{
    switch (t) {
    case VIF_TYPE_HOST:
        return "Host";
    case VIF_TYPE_AGENT:
        return "Agent";
    case VIF_TYPE_PHYSICAL:
        return "Physical";
    case VIF_TYPE_VIRTUAL:
        return "Virtual";
    case VIF_TYPE_XEN_LL_HOST:
        return "XenLL";
    case VIF_TYPE_GATEWAY:
        return "Gateway";
    case VIF_TYPE_STATS:
        return "Stats";
    case VIF_TYPE_VIRTUAL_VLAN:
        return "Virtual(Vlan)";
    case VIF_TYPE_MONITORING:
        return "Monitoring";
    default:
        return "Invalid";
    }

    return NULL;
}

static unsigned int
vr_get_if_type(char *type_str)
{
    if (!strncmp(type_str, VHOST_TYPE_STRING,
                strlen(VHOST_TYPE_STRING)))
        return VIF_TYPE_HOST;
    else if (!strncmp(type_str, AGENT_TYPE_STRING,
                strlen(AGENT_TYPE_STRING)))
        return VIF_TYPE_AGENT;
    else if (!strncmp(type_str, PHYSICAL_TYPE_STRING,
                strlen(PHYSICAL_TYPE_STRING)))
        return VIF_TYPE_PHYSICAL;
    else if (!strncmp(type_str, VIRTUAL_VLAN_TYPE_STRING,
                strlen(VIRTUAL_VLAN_TYPE_STRING)))
        return VIF_TYPE_VIRTUAL_VLAN;
    else if (!strncmp(type_str, VIRTUAL_TYPE_STRING,
                strlen(VIRTUAL_TYPE_STRING)))
        return VIF_TYPE_VIRTUAL;
    else if (!strncmp(type_str, XEN_LL_TYPE_STRING,
                strlen(XEN_LL_TYPE_STRING)))
        return VIF_TYPE_XEN_LL_HOST;
    else if (!strncmp(type_str, GATEWAY_TYPE_STRING,
                strlen(GATEWAY_TYPE_STRING)))
        return VIF_TYPE_GATEWAY;
    else if (!strncmp(type_str, STATS_TYPE_STRING,
                strlen(STATS_TYPE_STRING)))
        return VIF_TYPE_STATS;
    else if (!strncmp(type_str, MONITORING_TYPE_STRING,
                strlen(MONITORING_TYPE_STRING)))
        return VIF_TYPE_MONITORING;
    else
        Usage();

    return 0;
}

static char *
vr_if_flags(int flags)
{
    unsigned int i, array_size;

    bzero(flag_string, sizeof(flag_string));

    array_size = sizeof(flag_metadata) / sizeof(flag_metadata[0]);
    for (i = 0; i < array_size; i++) {
        if (flags & flag_metadata[i].vuf_flag)
            strcat(flag_string, flag_metadata[i].vuf_flag_symbol);
    }

    return flag_string;
}

static void
vr_interface_print_header(void)
{
    unsigned int i, array_size;

    array_size = sizeof(flag_metadata) / sizeof(flag_metadata[0]);

    printf("Vrouter Interface Table\n\n");

    printf("Flags: ");

    for (i = 0; i < array_size; i++) {
        if (i) {
            if (!(i % 4))
                printf("\n       ");
            else
                printf(", ");
        }
        printf("%s=%s", flag_metadata[i].vuf_flag_symbol,
                flag_metadata[i].vuf_flag_string);
    }

    printf("\n\n");
    return;
}

void
vr_vrf_assign_req_process(void *s)
{
    vr_vrf_assign_req *req = (vr_vrf_assign_req *)s;

    printf("%d:%d, ", req->var_vlan_id, req->var_vif_vrf);
    var_marker = req->var_vlan_id;

    return;
}

static void
vr_interface_print_head_space(void)
{
    int i;

    for (i = 0; i < 12; i++)
        printf(" ");
    return;
}

char *
vr_if_transport_string(vr_interface_req *req)
{
    switch (req->vifr_transport) {
    case VIF_TRANSPORT_VIRTUAL:
        return "Virtual";
        break;

    case VIF_TRANSPORT_ETH:
        return "Ethernet";
        break;

    case VIF_TRANSPORT_PMD:
        return "PMD";
        break;

    case VIF_TRANSPORT_SOCKET:
        return "Socket";
        break;

    default:
        break;
    }

    return "Unknown";
}

static void
vr_interface_core_print(void)
{
    if (core != (unsigned)-1) {
        printf("Core %u ", core);
    }
}

static void
vr_interface_nombufs_print(uint64_t nombufs)
{
    if (nombufs)
        printf(" no mbufs:%" PRId64, nombufs);
    printf("\n");
}

static void
vr_interface_pbem_counters_print(const char *title, bool print_always,
            uint64_t packets, uint64_t bytes, uint64_t errors,
            uint64_t nombufs)
{
    if (print_always || packets || bytes || errors) {
        vr_interface_print_head_space();
        vr_interface_core_print();
        printf("%s packets:%" PRId64 "  bytes:%" PRId64 " errors:%" PRId64,
                title, packets, bytes, errors);
        vr_interface_nombufs_print(nombufs);
    }
}

static void
vr_interface_pesm_counters_print(const char *title, bool print_always,
            uint64_t packets, uint64_t errors, uint64_t syscalls,
            uint64_t nombufs)
{
    if (print_always || packets || errors) {
        vr_interface_print_head_space();
        vr_interface_core_print();
        printf("%s packets:%" PRId64 " errors:%" PRId64,
                title, packets, errors);
        if (syscalls)
            printf(" syscalls:%" PRId64, syscalls);
        vr_interface_nombufs_print(nombufs);
    }
}

static void
vr_interface_pe_counters_print(const char *title, bool print_always,
            uint64_t packets, uint64_t errors)
{
    if (print_always || packets || errors) {
        vr_interface_print_head_space();
        vr_interface_core_print();
        printf("%s packets:%" PRId64 " errors:%" PRId64 "\n",
                title, packets, errors);
    }
}

static void
vr_interface_e_per_lcore_counters_print(const char *title, bool print_always,
            uint64_t *errors, uint32_t size)
{
    int i;

    if (print_always) {
        for (i = 0; i < size; i++) {
            vr_interface_print_head_space();
            vr_interface_core_print();
            printf("%s to lcore %d errors:%" PRId64 "\n", title, i, errors[i]);
        }
    } else {
        for (i = 0; i < size; i++) {
            if (errors[i]) {
                vr_interface_print_head_space();
                vr_interface_core_print();
                printf("%s to lcore %d errors:%" PRId64 "\n", title, i, errors[i]);
            }
        }
    }
}

void
vr_interface_req_process(void *s)
{
    char name[50];
    vr_interface_req *req = (vr_interface_req *)s;
    vr_interface_req rate_req_temp = {0};
    unsigned int printed = 0;
    bool print_zero = false; /* Do not print zeroed DPDK stats in --list mode */

    if (add_set)
        vr_ifindex = req->vifr_idx;

    if (!get_set && !list_set)
        return;

    if (rate_set) {
        print_zero = true; /* Print zeroed DPDK stats in --rate mode */

        rate_req_temp = *req;
        rate_req_temp.vifr_queue_ierrors_to_lcore = malloc(VR_MAX_CPUS * sizeof(uint64_t));
        memcpy(rate_req_temp.vifr_queue_ierrors_to_lcore,
                req->vifr_queue_ierrors_to_lcore,
                req->vifr_queue_ierrors_to_lcore_size * sizeof(uint64_t));

        rate_stats_diff(req);

        prev_req = rate_req_temp;
        memcpy(prev_req.vifr_queue_ierrors_to_lcore,
                rate_req_temp.vifr_queue_ierrors_to_lcore,
                rate_req_temp.vifr_queue_ierrors_to_lcore_size * sizeof(uint64_t));
    }

    printed = printf("vif%d/%d", req->vifr_rid, req->vifr_idx);
    for (; printed < 12; printed++)
        printf(" ");

    if (req->vifr_flags & VIF_FLAG_PMD) {
        printf("PMD: %d", req->vifr_os_idx);
    } else if (platform == DPDK_PLATFORM) {
        switch (req->vifr_type) {
        case VIF_TYPE_PHYSICAL:
            printf("PCI: %d:%d:%d.%d",
                    (req->vifr_os_idx >> 16), (req->vifr_os_idx >> 8) & 0xFF,
                    (req->vifr_os_idx >> 3) & 0x1F, (req->vifr_os_idx & 0x7));
            break;

        case VIF_TYPE_MONITORING:
            printf("Monitoring: %s for vif%d/%d", req->vifr_name,
                    req->vifr_rid, req->vifr_os_idx);
            break;

        default:
            if (req->vifr_name)
                printf("%s: %s", vr_if_transport_string(req),
                        req->vifr_name);
            break;
        }

    } else {
        printf("OS: %s", req->vifr_os_idx ?
                if_indextoname(req->vifr_os_idx, name): "NULL");
    }

    if (req->vifr_type == VIF_TYPE_PHYSICAL) {
        if (req->vifr_speed >= 0) {
            printf(" (Speed %d,", req->vifr_speed);
            if (req->vifr_duplex >= 0)
                printf(" Duplex %d", req->vifr_duplex);
            printf(")");
        }
    } else if (req->vifr_type == VIF_TYPE_VIRTUAL_VLAN) {
        printf(" Vlan(o/i)(,S): %d/%d", req->vifr_ovlan_id, req->vifr_vlan_id);
        if (req->vifr_src_mac_size && req->vifr_src_mac)
            printf(", "MAC_FORMAT, MAC_VALUE((uint8_t *)req->vifr_src_mac));
        printf(" Bridge Index: %d", req->vifr_bridge_idx);
    }

    if (req->vifr_parent_vif_idx >= 0)
        printf(" Parent:vif0/%d", req->vifr_parent_vif_idx);

    printf("\n");

    vr_interface_print_head_space();
    printf("Type:%s HWaddr:"MAC_FORMAT" IPaddr:%x\n",
            vr_get_if_type_string(req->vifr_type),
            MAC_VALUE((uint8_t *)req->vifr_mac), req->vifr_ip);
    vr_interface_print_head_space();
    printf("Vrf:%d Flags:%s MTU:%d Ref:%d\n", req->vifr_vrf,
            req->vifr_flags ? vr_if_flags(req->vifr_flags) : "NULL" ,
            req->vifr_mtu, req->vifr_ref_cnt);

    if (platform == DPDK_PLATFORM) {
        vr_interface_pbem_counters_print("RX device", print_zero,
                req->vifr_dev_ipackets, req->vifr_dev_ibytes,
                req->vifr_dev_ierrors, req->vifr_dev_inombufs);
        vr_interface_pesm_counters_print("RX port  ", print_zero,
                req->vifr_port_ipackets, req->vifr_port_ierrors,
                req->vifr_port_isyscalls, req->vifr_port_inombufs);
        vr_interface_pe_counters_print("RX queue ", print_zero,
                req->vifr_queue_ipackets, req->vifr_queue_ierrors);
        vr_interface_e_per_lcore_counters_print("RX queue", print_zero,
                req->vifr_queue_ierrors_to_lcore,
                req->vifr_queue_ierrors_to_lcore_size);
    }

    vr_interface_pbem_counters_print("RX", true, req->vifr_ipackets,
             req->vifr_ibytes, req->vifr_ierrors, 0);
    vr_interface_pbem_counters_print("TX", true, req->vifr_opackets,
             req->vifr_obytes, req->vifr_oerrors, 0);

    if (platform == DPDK_PLATFORM) {
        vr_interface_pe_counters_print("TX queue ", print_zero,
                req->vifr_queue_opackets, req->vifr_queue_oerrors);
        vr_interface_pesm_counters_print("TX port  ", print_zero,
                req->vifr_port_opackets, req->vifr_port_oerrors,
                req->vifr_port_osyscalls, 0);
        vr_interface_pbem_counters_print("TX device", print_zero,
                req->vifr_dev_opackets, req->vifr_dev_obytes,
                req->vifr_dev_oerrors, 0);
    }

    printf("\n");

    if (list_set)
        dump_marker = req->vifr_idx;

    if (get_set && req->vifr_flags & VIF_FLAG_SERVICE_IF) {
        vr_vrf_assign_dump = true;
        dump_pending = true;
        printf("VRF table(vlan:vrf):\n");
        vr_ifindex = req->vifr_idx;
    }

    return;
}

void
vr_response_process(void *s)
{
    vr_response_common_process((vr_response *)s, &dump_pending);
    return;
}

/*
 * create vhost interface in linux
 */
static int
vhost_create(void)
{
    int ret;
#if defined(__linux__)
    struct vn_if vhost;
    struct nl_response *resp;

    bzero(&vhost, sizeof(vhost));
    strncpy(vhost.if_name, if_name, sizeof(vhost.if_name) - 1);
    strncpy(vhost.if_kind, VHOST_KIND, sizeof(vhost.if_kind) - 1);
    memcpy(vhost.if_mac, vr_ifmac, sizeof(vhost.if_mac));
    ret = nl_build_if_create_msg(cl, &vhost, 0);
    if (ret)
        return ret;

    ret = nl_sendmsg(cl);
    if (ret <= 0)
        return ret;

    if ((ret = nl_recvmsg(cl)) > 0) {
        resp = nl_parse_reply(cl);
        if (resp && resp->nl_op)
            printf("%s\n", strerror(resp->nl_op));
    }
#elif defined(__FreeBSD__)
    struct ifreq ifr = { 0 };
    int s;
    int errsv;

    s = socket(PF_LOCAL, SOCK_DGRAM, 0);
    if (s < 0) {
        ret = s;
        errsv = errno;
        fprintf(stderr, "vhost_create: Failed to open socket.\n");
        goto ending;
    }

    strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name) - 1);

    ret = ioctl(s, SIOCIFCREATE, &ifr);
    if (ret < 0) {
        errsv = errno;
        fprintf(stderr, "vhost_create: Failed to create interface.\n");
        goto ending;
    }

    if (mac_set) {
        memcpy(ifr.ifr_addr.sa_data, vr_ifmac, ETHER_ADDR_LEN);
        ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
        ifr.ifr_addr.sa_family = AF_LOCAL;

        ret = ioctl(s, SIOCSIFLLADDR, &ifr);
        if (ret < 0) {
            errsv = errno;
            fprintf(stderr, "vhost_create: Failed to set MAC address.\n");
            goto ending;
        }
    }

ending:
    if (ret < 0)
        fprintf(stderr, "vhost_create: %s.\n", strerror(errsv));

    if (s >=0)
        close(s);
#else
#error "Unsupported platform"
#endif
    return ret;
}

static int
vr_intf_op(struct nl_client *cl, unsigned int op)
{
    int ret, vrf;
    bool dump = false;

    if (create_set)
        return vhost_create();

    if ((op == SANDESH_OP_DUMP) ||
            ((op == SANDESH_OP_GET) && !(add_set) && !(rate_set))) {
        vr_interface_print_header();
    }

op_retry:
    switch (op) {
    case SANDESH_OP_ADD:
        if (set_set)
            vrf = -1;
        else
            vrf = vrf_id;

        if (if_kindex < 0)
            if_kindex = 0;

        if (vindex_set)
            vr_ifindex = vif_index;

        if (vr_ifindex < 0)
            vr_ifindex = if_kindex;

        ret = vr_send_interface_add(cl, 0, if_name, if_kindex, vr_ifindex,
                if_xconnect_kindex, vr_if_type, vrf, vr_ifflags, vr_ifmac);
        break;

    case SANDESH_OP_DELETE:
        ret = vr_send_interface_delete(cl, 0, if_name, vr_ifindex);
        break;

    case SANDESH_OP_GET:
        /**
         * Implementation of getting per-core vif statistics is based on this
         * little trick to avoid making changes in how agent makes requests for
         * statistics. From vRouter's and agent's point of view, request for
         * stats for 0th core means a request for stats summed up for all the
         * cores. So cores are enumerated starting with 1.
         * Meanwhile, from user's point of view they are enumerated starting
         * with 0 (e.g. vif --list --core 0 means 'vif statistics for the very
         * first (0th) core'). This is how Linux enumerates CPUs, so it should
         * be more intuitive for the user.
         *
         * Agent is not aware of possibility of asking for per-core stats. Its
         * requests have vifr_core implicitly set to 0. So we need to make a
         * conversion between those enumerating systems. The vif utility
         * increments by 1 the core number user asked for. Then it is
         * decremented back in vRouter.
         */
        if (!vr_vrf_assign_dump) {
            ret = vr_send_interface_get(cl, 0, vr_ifindex, if_kindex, core + 1);
        } else {
            dump = true;
            ret = vr_send_vrf_assign_dump(cl, 0, vr_ifindex, var_marker);
        }
        break;

    case SANDESH_OP_DUMP:
        dump = true;
        ret = vr_send_interface_dump(cl, 0, dump_marker, core + 1);
        break;
    }

    if (ret < 0)
        return ret;


    ret = vr_recvmsg(cl, dump);
    if (ret <= 0)
        return ret;

    if (set_set) {
        ret = vr_send_vrf_assign_set(cl, 0, vr_ifindex, vlan_id, vrf_id);
        if (ret < 0)
            return ret;

        return vr_recvmsg(cl, dump);
    }

    if (dump_pending) {
        goto op_retry;
    }

    return 0;
}

static void
Usage()
{
    printf("Usage: vif [--create <intf_name> --mac <mac>]\n");
    printf("\t   [--add <intf_name> --mac <mac> --vrf <vrf>\n");
    printf("\t   \t--type [vhost|agent|physical|virtual|monitoring]\n");
    printf("\t   \t--xconnect <physical interface name>\n");
    printf("\t   \t--policy, --vhost-phys, --dhcp-enable]\n");
    printf("\t   \t--vif <vif ID>]\n");
    printf( "[--id <intf_id> --pmd --pci]\n");
    printf("\t   [--delete <intf_id>]\n");
    printf("\t   [--get <intf_id>][--kernel][--core <core number>][--rate]\n");
    printf("\t   [--set <intf_id> --vlan <vlan_id> --vrf <vrf_id>]\n");
    printf("\t   [--list][--core <core number>]\n");
    printf("\t   [--help]\n");

    exit(0);
}


enum if_opt_index {
    ADD_OPT_INDEX,
    CREATE_OPT_INDEX,
    GET_OPT_INDEX,
    RATE_OPT_INDEX,
    LIST_OPT_INDEX,
    VRF_OPT_INDEX,
    MAC_OPT_INDEX,
    DELETE_OPT_INDEX,
    POLICY_OPT_INDEX,
    PMD_OPT_INDEX,
    PCI_OPT_INDEX,
    KINDEX_OPT_INDEX,
    TYPE_OPT_INDEX,
    SET_OPT_INDEX,
    VLAN_OPT_INDEX,
    XCONNECT_OPT_INDEX,
    VIF_OPT_INDEX,
    DHCP_OPT_INDEX,
    VHOST_PHYS_OPT_INDEX,
    HELP_OPT_INDEX,
    VINDEX_OPT_INDEX,
    CORE_OPT_INDEX,
    MAX_OPT_INDEX
};

static struct option long_options[] = {
    [ADD_OPT_INDEX]         =   {"add",         required_argument,  &add_set,           1},
    [CREATE_OPT_INDEX]      =   {"create",      required_argument,  &create_set,        1},
    [GET_OPT_INDEX]         =   {"get",         required_argument,  &get_set,           1},
    [RATE_OPT_INDEX]        =   {"rate",        no_argument,        &rate_set,          1},
    [LIST_OPT_INDEX]        =   {"list",        no_argument,        &list_set,          1},
    [VRF_OPT_INDEX]         =   {"vrf",         required_argument,  &vrf_set,           1},
    [MAC_OPT_INDEX]         =   {"mac",         required_argument,  &mac_set,           1},
    [DELETE_OPT_INDEX]      =   {"delete",      required_argument,  &delete_set,        1},
    [POLICY_OPT_INDEX]      =   {"policy",      no_argument,        &policy_set,        1},
    [PMD_OPT_INDEX]         =   {"pmd",         no_argument,        &pmd_set,           1},
    [PCI_OPT_INDEX]         =   {"pci",         no_argument,        &pci_set,           1},
    [KINDEX_OPT_INDEX]      =   {"kernel",      no_argument,        &kindex_set,        1},
    [TYPE_OPT_INDEX]        =   {"type",        required_argument,  &type_set,          1},
    [SET_OPT_INDEX]         =   {"set",         required_argument,  &set_set,           1},
    [VLAN_OPT_INDEX]        =   {"vlan",        required_argument,  &vlan_set,          1},
    [VHOST_PHYS_OPT_INDEX]  =   {"vhost-phys",  no_argument,        &vhost_phys_set,    1},
    [XCONNECT_OPT_INDEX]    =   {"xconnect",    required_argument,  &xconnect_set,      1},
    [VIF_OPT_INDEX]         =   {"vif",         required_argument,  &vif_set,           1},
    [DHCP_OPT_INDEX]        =   {"dhcp-enable", no_argument,        &dhcp_set,          1},
    [HELP_OPT_INDEX]        =   {"help",        no_argument,        &help_set,          1},
    [VINDEX_OPT_INDEX]      =   {"id",          required_argument,  &vindex_set,        1},
    [CORE_OPT_INDEX]        =   {"core",        required_argument,  &core_set,          1},
    [MAX_OPT_INDEX]         =   { NULL,         0,                  NULL,               0},
};

static void
parse_long_opts(int option_index, char *opt_arg)
{
    errno = 0;

    if (!*(long_options[option_index].flag))
        *(long_options[option_index].flag) = 1;

    switch (option_index) {
    case ADD_OPT_INDEX:
        strncpy(if_name, opt_arg, sizeof(if_name) - 1);
        if_kindex = if_nametoindex(opt_arg);
        if (isdigit(opt_arg[0]))
            if_pmdindex = strtol(opt_arg, NULL, 0);
        vr_op = SANDESH_OP_ADD;
        break;

    case CREATE_OPT_INDEX:
        strncpy(if_name, opt_arg, sizeof(if_name) - 1);
        break;

    case VRF_OPT_INDEX:
        vrf_id = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        break;

    case MAC_OPT_INDEX:
        mac_opt = ether_aton(opt_arg);
        if (mac_opt)
            memcpy(vr_ifmac, mac_opt, sizeof(vr_ifmac));
        break;

    case DELETE_OPT_INDEX:
        vr_op = SANDESH_OP_DELETE;
        vr_ifindex = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        break;

    case GET_OPT_INDEX:
        vr_op = SANDESH_OP_GET;
        vr_ifindex = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        break;

    case VIF_OPT_INDEX:
        /* we carry monitored vif index in OS index field */
        if_kindex = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        break;

    case VINDEX_OPT_INDEX:
        vif_index = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        break;

    case POLICY_OPT_INDEX:
        vr_ifflags |= VIF_FLAG_POLICY_ENABLED;
        break;

    case PMD_OPT_INDEX:
        vr_ifflags |= VIF_FLAG_PMD;
        break;

    case LIST_OPT_INDEX:
        vr_op = SANDESH_OP_DUMP;
        break;

    case CORE_OPT_INDEX:
        core = (unsigned)strtol(opt_arg, NULL, 0);
        if (errno) {
            printf("Error parsing core %s: %s (%d)\n", opt_arg,
                    strerror(errno), errno);
            Usage();
        }
        break;

    case TYPE_OPT_INDEX:
        vr_if_type = vr_get_if_type(optarg);
        if (vr_if_type == VIF_TYPE_HOST)
            need_xconnect_if = true;
        if (vr_if_type == VIF_TYPE_MONITORING) {
            if (platform != DPDK_PLATFORM)
                Usage();

            need_vif_id = true;
            /* set default values for mac and vrf */
            vrf_id = 0;
            vrf_set = 1;
            vr_ifmac[0] = 0x2; /* locally administered */
            mac_set = 1;
        }
        break;

    case SET_OPT_INDEX:
        vr_op = SANDESH_OP_ADD;
        vr_ifindex = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        break;

    case VLAN_OPT_INDEX:
        vr_ifflags |= VIF_FLAG_SERVICE_IF;
        vlan_id = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        break;

    case XCONNECT_OPT_INDEX:
        if_xconnect_kindex = if_nametoindex(opt_arg);
        if (isdigit(opt_arg[0])) {
            if_pmdindex = strtol(opt_arg, NULL, 0);
        } else if (!if_xconnect_kindex) {
            printf("%s does not seem to be a valid physical interface name\n",
                    opt_arg);
            Usage();
        }

        break;

    case DHCP_OPT_INDEX:
        vr_ifflags |= VIF_FLAG_DHCP_ENABLED;
        break;

    case VHOST_PHYS_OPT_INDEX:
        vr_ifflags |= VIF_FLAG_VHOST_PHYS;
        break;

    default:
        break;
    }

    return;
}

static void
validate_options(void)
{
    unsigned int sum_opt = 0, i;

    for (i = 0; i < (sizeof(long_options) / sizeof(long_options[0]));
                i++) {
        if (long_options[i].flag)
            sum_opt += *(long_options[i].flag);
    }

    if (!sum_opt || help_set)
        Usage();

    if (pmd_set || pci_set) {
        if_kindex = if_pmdindex;
        if_xconnect_kindex = if_pmdindex;
    }

    if (create_set) {
        if ((sum_opt > 1) && (sum_opt != 2 || !mac_set))
            Usage();
        return;
    }
    if (get_set) {
        if ((sum_opt > 1) && (sum_opt != 3) && (!kindex_set && !core_set && !rate_set))
            Usage();
        return;
    }
    if (delete_set) {
        if (sum_opt > 1)
            Usage();
        return;
    }

    if (list_set) {
        if (!core_set) {
            if (sum_opt > 1)
                Usage();
        } else {
            if (sum_opt != 2)
                Usage();
        }
        return;
    }

    if (add_set) {
        if (get_set || list_set)
            Usage();
        if (!vrf_set || !mac_set || !type_set)
            Usage();
        if (need_xconnect_if && !xconnect_set)
            Usage();
        if (need_vif_id && !vif_set)
            Usage();
        return;
    }

    if (set_set) {
        if (sum_opt != 3 || !vrf_set || !vlan_set)
            Usage();
        return;
    }

    /**
     * Statistics per CPU core could be requested as an additional parameter
     * to --list or --get.
     */
    if (core_set) {
        if (!list_set || !get_set)
            Usage();
    }
    if (rate_set) {
        if (!get_set) {
            Usage();
        }
    }

    return;
}


static void
rate_stats_diff(vr_interface_req *req)
{
    struct timeval now;
    int64_t diff_ms = 0, i = 0;

    gettimeofday(&now, NULL);
    diff_ms = (now.tv_sec - last_time.tv_sec) * 1000;
    diff_ms += (now.tv_usec - last_time.tv_usec) / 1000;
    last_time = now;

    /* RX */
    req->vifr_dev_ipackets =
        ((req->vifr_dev_ipackets -  prev_req.vifr_dev_ipackets) * 1000)/diff_ms;
    req->vifr_dev_ibytes =
        ((req->vifr_dev_ibytes -  prev_req.vifr_dev_ibytes) * 1000)/diff_ms;
    req->vifr_dev_ierrors =
        ((req->vifr_dev_ierrors - prev_req.vifr_dev_ierrors) * 1000)/diff_ms;
    req->vifr_dev_inombufs =
        ((req->vifr_dev_inombufs - prev_req.vifr_dev_inombufs) * 1000)/diff_ms;

    req->vifr_port_ipackets =
        ((req->vifr_port_ipackets - prev_req.vifr_port_ipackets) * 1000)/diff_ms;
    req->vifr_port_ierrors =
        ((req->vifr_port_ierrors - prev_req.vifr_port_ierrors) * 1000)/diff_ms;
    req->vifr_port_isyscalls =
        ((req->vifr_port_isyscalls - prev_req.vifr_port_isyscalls) * 1000)/diff_ms;
    req->vifr_port_inombufs =
        ((req->vifr_port_inombufs - prev_req.vifr_port_inombufs) * 1000)/diff_ms;

    req->vifr_queue_ipackets =
        ((req->vifr_queue_ipackets - prev_req.vifr_queue_ipackets) * 1000)/diff_ms;
    req->vifr_queue_ierrors =
        ((req->vifr_queue_ierrors - prev_req.vifr_queue_ierrors) * 1000)/diff_ms;
    for (i = 0; i < req->vifr_queue_ierrors_to_lcore_size; i++) {
        req->vifr_queue_ierrors_to_lcore[i] =
            ((req->vifr_queue_ierrors_to_lcore[i] -
                prev_req.vifr_queue_ierrors_to_lcore[i]) * 1000)/diff_ms;
    }

    req->vifr_ipackets =
        ((req->vifr_ipackets - prev_req.vifr_ipackets) * 1000)/diff_ms;
    req->vifr_ibytes =
        ((req->vifr_ibytes - prev_req.vifr_ibytes) * 1000)/diff_ms;
    req->vifr_ierrors =
        ((req->vifr_ierrors - prev_req.vifr_ierrors) * 1000)/diff_ms;

    /* TX */
    req->vifr_opackets =
        ((req->vifr_opackets - prev_req.vifr_opackets) * 1000)/diff_ms;
    req->vifr_obytes =
        ((req->vifr_obytes - prev_req.vifr_obytes) * 1000)/diff_ms;
    req->vifr_oerrors =
        ((req->vifr_oerrors - prev_req.vifr_oerrors) * 1000)/diff_ms;

    req->vifr_queue_opackets =
        ((req->vifr_queue_opackets - prev_req.vifr_queue_opackets) * 1000)/diff_ms;
    req->vifr_queue_oerrors =
        ((req->vifr_queue_oerrors - prev_req.vifr_queue_oerrors) * 1000)/diff_ms;

    req->vifr_port_opackets =
        ((req->vifr_port_opackets - prev_req.vifr_port_opackets) * 1000)/diff_ms;
    req->vifr_port_oerrors =
        ((req->vifr_port_oerrors - prev_req.vifr_port_oerrors) * 1000)/diff_ms;

    req->vifr_dev_opackets =
        ((req->vifr_dev_opackets - prev_req.vifr_dev_opackets  ) * 1000)/diff_ms;
    req->vifr_dev_obytes =
        ((req->vifr_dev_obytes - prev_req.vifr_dev_obytes) * 1000)/diff_ms;
    req->vifr_dev_oerrors =
        ((req->vifr_dev_oerrors - prev_req.vifr_dev_oerrors) * 1000)/diff_ms;

}

static void
rate_stats(struct nl_client *cl, unsigned int vr_op)
{
    struct tm *tm;
    char fmt[80] = {0};

    gettimeofday(&last_time, NULL);
    while (true) {
        usleep(1000000);
        if (system("clear") == -1 ) {
            fprintf(stderr, "Error: system() failed.\n");
            exit(1);
        }
        printf("Interface rate statistics\n");
        printf("-------------------------\n\n");

        if (vr_intf_op(cl, vr_op)) {
            fprintf(stderr, "Communication problem with vRouter.\n\n");
            exit(1);
        }

        tm = localtime(&last_time.tv_sec);
        if (tm) {
            strftime(fmt, sizeof(fmt), "%Y-%m-%d %H:%M:%S %z", tm);
            printf("%s \n", fmt);
        }
    }
}

int
main(int argc, char *argv[])
{
    int ret, opt, option_index;
    /*
     * the proto of the socket changes based on whether we are creating an
     * interface in linux or doing an operation in vrouter
     */
    unsigned int sock_proto = NETLINK_GENERIC;

    parse_ini_file();
    platform = get_platform();

    while ((opt = getopt_long(argc, argv, "ba:c:d:g:klm:t:v:p:C:DPi:",
                    long_options, &option_index)) >= 0) {
        switch (opt) {
            case 'a':
                add_set = 1;
                parse_long_opts(ADD_OPT_INDEX, optarg);
                break;

            case 'c':
                create_set = 1;
                parse_long_opts(CREATE_OPT_INDEX, optarg);
                break;

            case 'd':
                delete_set = 1;
                parse_long_opts(DELETE_OPT_INDEX, optarg);
                break;

            case 'g':
                get_set = 1;
                parse_long_opts(GET_OPT_INDEX, optarg);
                break;

            case 'k':
                parse_long_opts(KINDEX_OPT_INDEX, optarg);
                kindex_set = 1;
                break;

            case 'l':
            case 'b':
                list_set = 1;
                parse_long_opts(LIST_OPT_INDEX, NULL);
                break;

            case 'm':
                mac_set = 1;
                parse_long_opts(MAC_OPT_INDEX, optarg);
                break;

            case 'v':
                vrf_set = 1;
                parse_long_opts(VRF_OPT_INDEX, optarg);
                break;

            case 'p':
                policy_set = 1;
                parse_long_opts(POLICY_OPT_INDEX, NULL);
                break;

            case 'D':
                pmd_set = 1;
                parse_long_opts(PMD_OPT_INDEX, NULL);
                break;

            case 'P':
                pci_set = 1;
                parse_long_opts(PCI_OPT_INDEX, NULL);
                break;

            case 't':
                type_set = 1;
                parse_long_opts(TYPE_OPT_INDEX, optarg);
                break;

            case 'i':
                vindex_set = 1;
                parse_long_opts(VINDEX_OPT_INDEX, NULL);
                break;

            case 'C':
                core_set = 1;
                parse_long_opts(CORE_OPT_INDEX, optarg);
                break;

            case 0:
                parse_long_opts(option_index, optarg);
                break;

            case '?':
            default:
                Usage();
        }
    }

    validate_options();

    sock_proto = VR_NETLINK_PROTO_DEFAULT;
#if defined(__linux__)
    if (create_set)
        sock_proto = NETLINK_ROUTE;
#endif
    cl = vr_get_nl_client(sock_proto);
    if (!cl) {
        printf("Error registering NetLink client: %s (%d)\n",
                strerror(errno), errno);
        exit(-ENOMEM);
    }
    if (add_set) {
        /*
         * for addition, we need to see whether the interface already
         * exists in vrouter or not. so, get can return error if the
         * interface does not exist in vrouter
         */
        ignore_error = true;
        vr_intf_op(cl, SANDESH_OP_GET);
        ignore_error = false;
    }
    if (!rate_set) {
        vr_intf_op(cl, vr_op);
    } else {
        prev_req.vifr_queue_ierrors_to_lcore = malloc(VR_MAX_CPUS * sizeof(uint64_t));
        memset(prev_req.vifr_queue_ierrors_to_lcore, 0, VR_MAX_CPUS * sizeof(uint64_t));
        rate_stats(cl, vr_op);
    }
    return 0;
}
