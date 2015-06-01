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
static int if_vif_index = -1;
static short vlan_id = -1;
static int vr_ifflags;
static short core = -1;

static int add_set, create_set, get_set, list_set;
static int kindex_set, type_set, help_set, set_set, vlan_set, dhcp_set;
static int vrf_set, mac_set, delete_set, policy_set, pmd_set, vindex_set, pci_set;
static int xconnect_set, vif_set, vhost_phys_set, core_set;

static unsigned int vr_op, vr_if_type;
static bool ignore_error = false, dump_pending = false;
static bool response_pending = true;
static bool vr_vrf_assign_dump = false;
static int dump_marker = -1, var_marker = -1;

static int8_t vr_ifmac[6];
static struct ether_addr *mac_opt;

static void Usage(void);

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

    if (core_set && --core > -1)
        printf("Statistics for core %d\n\n", core);

    if (core_set)
        return;

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
void
vr_interface_req_process(void *s)
{
    char name[50];
    vr_interface_req *req = (vr_interface_req *)s;
    unsigned int printed = 0;
    int platform = get_platform();

    if (add_set)
        vr_ifindex = req->vifr_idx;

    if (!get_set && !list_set)
        return;

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

    vr_interface_print_head_space();
    printf("RX packets:%" PRId64 "  bytes:%" PRId64 " errors:%" PRId64 "\n",
            req->vifr_ipackets,
            req->vifr_ibytes, req->vifr_ierrors);
    vr_interface_print_head_space();
    printf("TX packets:%" PRId64 "  bytes:%" PRId64 " errors:%" PRId64 "\n",
            req->vifr_opackets,
            req->vifr_obytes, req->vifr_oerrors);

    /* Additional DPDK-specific statistics */
    if (platform == DPDK_PLATFORM) {
        vr_interface_print_head_space();
        printf("Packets sent to vif: %" PRId64"  Drops:%" PRId64 "  \n",
            req->vifr_ifenqpkts, req->vifr_ifenqdrops);
        vr_interface_print_head_space();
        printf("Packets enqueued on TX ring: %" PRId64"  Drops:%" PRId64 "  \n",
            req->vifr_iftxrngenqpkts, req->vifr_iftxrngenqdrops);
        vr_interface_print_head_space();
        printf("Packets received on vif: %" PRId64"  Drops:%" PRId64 "  \n",
            req->vifr_ifdeqpkts, req->vifr_ifdeqdrops);
        /**
         * TODO: when we hash MPLSoGRE packets to different lcores, it should
         * apply to virtual as well as physical interfaces.
         */
        if (req->vifr_type == VIF_TYPE_VIRTUAL
                                /* || req->vifr_type == VIF_TYPE_PHYSICAL */) {
            vr_interface_print_head_space();
            printf("Packets enqueued on RX ring: %" PRId64"  Drops:%" PRId64 "  \n",
                req->vifr_ifrxrngenqpkts, req->vifr_ifrxrngenqdrops);
        }
    }
    printf("\n");

    if (list_set)
        dump_marker = req->vifr_idx;

    if (get_set && req->vifr_flags & VIF_FLAG_SERVICE_IF) {
        vr_vrf_assign_dump = true;
        printf("VRF table(vlan:vrf):\n");
        vr_ifindex = req->vifr_idx;
    }

    if (vr_op != SANDESH_OP_DUMP)
        response_pending = false;

    return;
}


void
vr_response_process(void *s)
{
    vr_response *resp = (vr_response *)s;

    response_pending = false;
    if (resp->resp_code < 0 && !ignore_error)
        printf("%s\n", strerror(-resp->resp_code));

    if (vr_op == SANDESH_OP_DUMP) {
        if (resp->resp_code > 0)
            response_pending = true;

        if (resp->resp_code & VR_MESSAGE_DUMP_INCOMPLETE) {
            response_pending = true;
            dump_pending = true;
        } else {
            dump_pending = false;
        }
    } else if (vr_op == SANDESH_OP_GET && vr_vrf_assign_dump) {
        if (!(resp->resp_code & VR_MESSAGE_DUMP_INCOMPLETE)) {
            vr_vrf_assign_dump = false;
        }
    }

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
vr_intf_send_msg(void *request, char *request_string)
{
    int ret, error, attr_len;
    struct nl_response *resp;
    struct nlmsghdr *nlh;

    /* nlmsg header */
    ret = nl_build_nlh(cl, cl->cl_genl_family_id, NLM_F_REQUEST);
    if (ret) {
        return ret;
    }

    /* Generic nlmsg header */
    ret = nl_build_genlh(cl, SANDESH_REQUEST, 0);
    if (ret) {
        return ret;
    }

    attr_len = nl_get_attr_hdr_size();

    error = 0;
    ret = sandesh_encode(request, request_string, vr_find_sandesh_info,
                             (nl_get_buf_ptr(cl) + attr_len),
                             (nl_get_buf_len(cl) - attr_len), &error);
    if (ret <= 0) {
        return ret;
    }

    /* Add sandesh attribute */
    nl_build_attr(cl, ret, NL_ATTR_VR_MESSAGE_PROTOCOL);
    nl_update_nlh(cl);

    response_pending = true;
    /* Send the request to kernel */
    ret = nl_sendmsg(cl);

    while (response_pending) {
        if ((ret = nl_recvmsg(cl)) > 0) {
            resp = nl_parse_reply(cl);
            if (resp->nl_op == SANDESH_REQUEST) {
                sandesh_decode(resp->nl_data, resp->nl_len,
                               vr_find_sandesh_info, &ret);
            } else if (resp->nl_type == NL_MSG_TYPE_DONE) {
                response_pending = false;
            }
        }

        nlh = (struct nlmsghdr *)cl->cl_buf;
        if (!nlh->nlmsg_flags)
            break;
    }

    return 0;
}

static int
vr_intf_set(void)
{
    vr_vrf_assign_req va_req;

    va_req.h_op = SANDESH_OP_ADD;
    va_req.var_rid = 0;
    va_req.var_vif_index = vr_ifindex;
    va_req.var_vif_vrf = vrf_id;
    va_req.var_vlan_id = vlan_id;

    return vr_intf_send_msg(&va_req, "vr_vrf_assign_req");
}


static int
vr_vrf_assign_dump_request(void)
{
    vr_vrf_assign_req va_req;

    va_req.h_op = SANDESH_OP_DUMP;
    va_req.var_vif_index = vr_ifindex;
    va_req.var_marker = var_marker;

    while (vr_vrf_assign_dump)
        vr_intf_send_msg(&va_req, "vr_vrf_assign_req");

    printf("\n");

    return 0;
}

static int
vr_intf_op(unsigned int op)
{
    int ret;
    vr_interface_req intf_req;
    int platform = get_platform();
    if (create_set)
        return vhost_create();
op_retry:
    memset(&intf_req, 0 , sizeof(intf_req));

    if (set_set)
        intf_req.vifr_vrf = -1;
    else
        intf_req.vifr_vrf = vrf_id;

    intf_req.h_op = op;
    intf_req.vifr_mac_size = 6;
    intf_req.vifr_mac = vr_ifmac;
    intf_req.vifr_ip = 0;
    intf_req.vifr_name = if_name;
    if (op == SANDESH_OP_DUMP)
        intf_req.vifr_marker = dump_marker;

    switch (op) {
    case SANDESH_OP_ADD:
        if (if_kindex < 0)
            if_kindex = 0;
        intf_req.vifr_os_idx = if_kindex;
        if (vr_ifindex < 0)
            vr_ifindex = if_kindex;
        if (vindex_set)
            intf_req.vifr_idx = vif_index;
        else
            intf_req.vifr_idx = vr_ifindex;
        intf_req.vifr_rid = 0;
        intf_req.vifr_type = vr_if_type;
        if (vr_if_type == VIF_TYPE_HOST) {
            intf_req.vifr_cross_connect_idx = if_xconnect_kindex;
        } else if (vr_if_type == VIF_TYPE_MONITORING) {
            if (platform == DPDK_PLATFORM) {
                /* we carry vif index in OS index field */
                intf_req.vifr_os_idx = if_vif_index;
            } else {
                printf("Error adding interface: " MONITORING_TYPE_STRING
                    " type should be used for vRouter/DPDK only\n");
                exit(-EINVAL);
            }
        }
        intf_req.vifr_flags = vr_ifflags;

        break;

    case SANDESH_OP_DELETE:
        intf_req.vifr_idx = vr_ifindex;
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
        intf_req.vifr_core = ++core;

        /*
         * this logic is slightly complicated. if --kernel option is set
         * for get or when if_kindex is set for add doing a get, we should
         * get true in the first if. else it is a regular get with vr ifindex
         */
        if (kindex_set || if_kindex != -1) {
            intf_req.vifr_idx = -1;
            if (vr_ifindex >= 0)
                intf_req.vifr_os_idx = vr_ifindex;
            else
                intf_req.vifr_os_idx = if_kindex;
        } else
            intf_req.vifr_idx = vr_ifindex;
        break;

    case SANDESH_OP_DUMP:
        intf_req.vifr_core = ++core;
        break;
    }

    /* only want to print the first time */
    if (((op == SANDESH_OP_DUMP) && !(dump_pending))
            || (op == SANDESH_OP_GET)) {
        vr_interface_print_header();
    }

    ret = vr_intf_send_msg(&intf_req, "vr_interface_req");
    if (ret < 0)
        return ret;

    if (set_set)
        ret = vr_intf_set();
    else if (get_set)
        if (vr_vrf_assign_dump)
            ret = vr_vrf_assign_dump_request();

    if (dump_pending)
        goto op_retry;

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
    printf("\t   [--get <intf_id>][--kernel][--core <core number>]\n");
    printf("\t   [--set <intf_id> --vlan <vlan_id> --vrf <vrf_id>]\n");
    printf("\t   [--list][--core <core number>]\n");
    printf("\t   [--help]\n");

    exit(0);
}


enum if_opt_index {
    ADD_OPT_INDEX,
    CREATE_OPT_INDEX,
    GET_OPT_INDEX,
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
        core = (short)strtoul(opt_arg, NULL, 0);
        if (core < 0)
            core = 0;
        break;

    case TYPE_OPT_INDEX:
        vr_if_type = vr_get_if_type(optarg);
        if (vr_if_type == VIF_TYPE_HOST)
            need_xconnect_if = true;
        if (vr_if_type == VIF_TYPE_MONITORING) {
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
            printf("%s does not seem to be a  valid physical interface name\n",
                    opt_arg);
            Usage();
        }

        break;

    case VIF_OPT_INDEX:
        if_vif_index = strtol(opt_arg, NULL, 0);
        vr_ifmac[sizeof(vr_ifmac) - 1] = if_vif_index & 0xFF;
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
        if ((sum_opt > 1) && (sum_opt != 3) && (!kindex_set && !core_set))
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

    return;
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

    cl = nl_register_client();
    if (!cl) {
        printf("Error registering NetLink client: %s (%d)\n",
                strerror(errno), errno);
        exit(-ENOMEM);
    }

    parse_ini_file();

#if defined(__linux__)
    if (create_set)
        sock_proto = NETLINK_ROUTE;
    else
        sock_proto = get_protocol();
#endif

    ret = nl_socket(cl, get_domain(), get_type(), sock_proto);
    if (ret <= 0) {
        printf("Error creating NetLink socket: %s (%d)\n",
                strerror(errno), errno);
        exit(1);
    }

    ret = nl_connect(cl, get_ip(), get_port());
    if (ret < 0) {
        printf("Error connecting to NetLink socket: %s (%d)\n",
                strerror(errno), errno);
        exit(1);
    }

    if (sock_proto == NETLINK_GENERIC)
        if (vrouter_get_family_id(cl) <= 0) {
            printf("Error getting NetLink family: %s (%d)\n",
                    strerror(errno), errno);
            return -1;
        }

    if (add_set) {
        /*
         * for addition, we need to see whether the interface already
         * exists in vrouter or not. so, get can return error if the
         * interface does not exist in vrouter
         */
        ignore_error = true;
        vr_intf_op(SANDESH_OP_GET);
        ignore_error = false;
    }

    vr_intf_op(vr_op);

    return 0;
}
