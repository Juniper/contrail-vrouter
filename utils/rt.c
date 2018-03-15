/*
 *  rt.c
 *
 *  Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <inttypes.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>

#include <net/if.h>

#if defined(__linux__) || defined(_WIN32)
#include <netinet/ether.h>
#else
#include <net/ethernet.h>
#endif

#include "vr_types.h"
#include "vr_packet.h"
#include "vr_nexthop.h"
#include "nl_util.h"
#include "vr_mpls.h"
#include "vr_defs.h"
#include "vr_route.h"
#include "vr_bridge.h"
#include "vr_os.h"
#include "ini_parser.h"
#include "vr_mem.h"
#include "vrouter.h"

static struct nl_client *cl;
static int resp_code;

static uint8_t rt_prefix[16], rt_marker[16];

static bool cmd_proxy_set = false;
static bool cmd_trap_set = false;
static bool cmd_flood_set = false;

static int cmd_set, dump_set, get_set, monitor_set;
static int family_set, help_set, vrf_set;
static int cust_flags;

static int cmd_prefix_set;
static int cmd_dst_mac_set;

static int cmd_vrf_id = -1, cmd_family_id;
static int cmd_op = -1;

static int cmd_nh_id = -1;
static char *cmd_prefix_string, *cmd_plen_string;
static uint8_t cmd_prefix[16], cmd_src[16];
static uint32_t cmd_plen = 0;
static int32_t cmd_label;
static uint32_t cmd_replace_plen = 0xFFFFFFFF;
static char cmd_dst_mac[6];
static bool dump_pending;

static int monitor = 0;

static void Usage(void);
static void usage_internal(void);

static void bridge_table_data_process(void *s_req);

#define INET_FAMILY_STRING      "inet"
#define BRIDGE_FAMILY_STRING    "bridge"
#define INET6_FAMILY_STRING     "inet6"

static int mem_fd = -1;
static struct bridge_table {
    unsigned int bt_size;
    unsigned int bt_num_entries;
    struct vr_bridge_entry *bt_entries;
} vr_bridge_table;


struct vr_util_flags inet_flags[] = {
    {VR_RT_LABEL_VALID_FLAG,    "L",    "Label Valid"   },
    {VR_RT_ARP_PROXY_FLAG,      "P",    "Proxy ARP"     },
    {VR_RT_ARP_TRAP_FLAG,       "T",    "Trap ARP"      },
    {VR_RT_ARP_FLOOD_FLAG,      "F",    "Flood ARP"     },
};

struct vr_util_flags bridge_flags[] = {
    {VR_BE_LABEL_VALID_FLAG,      "L",    "Label Valid"         },
    {VR_BE_FLOOD_DHCP_FLAG,       "Df",   "DHCP flood"          },
    {VR_BE_MAC_MOVED_FLAG,        "Mm",   "Mac Moved"           },
    {VR_BE_L2_CONTROL_DATA_FLAG,  "L2c",  "L2 Evpn Control Word"},
    {VR_BE_MAC_NEW_FLAG,          "N",    "New Entry"           },
    {VR_BE_EVPN_CONTROL_PROCESSING_FLAG, "Ec",    "EvpnControlProcessing" },
};

static void
dump_legend(int family)
{
    unsigned int i, array_size;
    struct vr_util_flags *rt_flags;

    switch (family) {
    case AF_INET:
    case AF_INET6:
        array_size = sizeof(inet_flags) / sizeof(inet_flags[0]);
        rt_flags = inet_flags;
        break;

    case AF_BRIDGE:
        array_size = sizeof(bridge_flags) / sizeof(bridge_flags[0]);
        rt_flags = bridge_flags;
        break;

    default:
        return;
    }

    printf("Flags: ");
    for (i = 0; i < array_size; i++) {
        printf("%s=%s", rt_flags[i].vuf_flag_symbol,
                rt_flags[i].vuf_flag_string);
        if (i != (array_size - 1))
            printf(", ");
    }

    printf("\n");
    return;
}

static int
family_string_to_id(char *fname)
{
    if (!strncmp(fname, INET6_FAMILY_STRING, strlen(INET6_FAMILY_STRING)))
        return AF_INET6;
    else if (!strncmp(fname, INET_FAMILY_STRING, strlen(INET_FAMILY_STRING)))
        return AF_INET;
    else if (!strncmp(fname, BRIDGE_FAMILY_STRING, strlen(BRIDGE_FAMILY_STRING)))
        return AF_BRIDGE;

    return -1;
}

static void
vr_bridge_print_route(uint8_t *mac, unsigned int index,
        unsigned int flags, unsigned int label,
        unsigned int nh_id, uint64_t packets)
{
    int ret, i;
    char flag_string[32];

    memset(flag_string, 0, sizeof(flag_string));
    if (flags & VR_BE_LABEL_VALID_FLAG)
        strcat(flag_string, "L");
    if (flags & VR_BE_FLOOD_DHCP_FLAG)
        strcat(flag_string, "Df");
    if (flags & VR_BE_MAC_MOVED_FLAG)
        strcat(flag_string, "Mm");
    if (flags & VR_BE_L2_CONTROL_DATA_FLAG)
        strcat(flag_string, "L2c");
    if (flags & VR_BE_MAC_NEW_FLAG)
        strcat(flag_string, "N");
    if (flags & VR_BE_EVPN_CONTROL_PROCESSING_FLAG)
        strcat(flag_string, "Ec");

    ret = printf("%-9d", index);
    for (i = ret; i < 12; i++)
        printf(" ");

    ret = printf("%s", ether_ntoa((struct ether_addr *)(mac)));
    for (i = ret; i < 20; i++)
        printf(" ");

    ret = printf(" %9s", flag_string);

    for (i = 0; i < 11; i++)
        printf(" ");

    if (flags & VR_BE_LABEL_VALID_FLAG)
        ret = printf(" %9d", label);
    else
        ret = printf(" %9c", '-');

    for (i = 0; i < 6; i++)
        printf(" ");
    printf("%7d", nh_id);

    for (i = 0; i < 4; i++)
        printf(" ");
    printf("%12" PRIu64 "\n", packets);

    return;
}

static void
vr_print_route_json(vr_route_req *rt)
{
    char addr[INET6_ADDRSTRLEN];

    printf("{");
    printf("\"operation\":");
    if (rt->h_op == SANDESH_OP_ADD)
        printf("\"add\"");
    else if (rt->h_op == SANDESH_OP_DEL)
        printf("\"delete\"");
    else
        printf("\"unknown\"");

    printf(",\"family\":");
    if (rt->rtr_family == AF_INET)
        printf("\"AF_INET\"");
    else if (rt->rtr_family == AF_INET6)
        printf("\"AF_INET6\"");
    else if (rt->rtr_family == AF_BRIDGE)
        printf("\"AF_BRIDGE\"");
    else
        printf("\"unknown\"");

    if ((rt->rtr_family == AF_INET) ||
        (rt->rtr_family == AF_INET6)) {
        printf(",\"vrf_id\":%d", rt->rtr_vrf_id);

        if (rt->rtr_prefix_size) {
            inet_ntop(rt->rtr_family, rt->rtr_prefix, addr, sizeof(addr));
            printf(",\"prefix\":%d", rt->rtr_prefix_len);
            printf(",\"address\":\"%s\"", addr);
            printf(",\"nh_id\":%d", rt->rtr_nh_id);
        }

        printf(",\"flags\":{\"label_valid\":%s, \"arp_proxy\":%s, \"arp_trap\":%s, \"arp_flood\":%s}",
            rt->rtr_label_flags & VR_RT_LABEL_VALID_FLAG ? "true" : "false",
            rt->rtr_label_flags & VR_RT_ARP_PROXY_FLAG ? "true" : "false",
            rt->rtr_label_flags & VR_RT_ARP_TRAP_FLAG ? "true" : "false",
            rt->rtr_label_flags & VR_RT_ARP_FLOOD_FLAG ? "true" : "false");

        if (rt->rtr_label_flags & VR_RT_LABEL_VALID_FLAG)
            printf(",\"label\":%d", rt->rtr_label);

        if (rt->rtr_mac_size) {
            printf(",\"mac_address\":\"%s\"", ether_ntoa((struct ether_addr *)(rt->rtr_mac)));
            printf(",\"mac_index\":%d", rt->rtr_index);
        }
    }
    printf("}\n");
    fflush(stdout);
}

static void
route_req_process(void *s_req)
{
    int ret = 0, i;
    char addr[INET6_ADDRSTRLEN];
    char flags[32];
    vr_route_req *rt = (vr_route_req *)s_req;

    if (monitor) {
        vr_print_route_json(rt);
        return;
    }

    if ((rt->rtr_family == AF_INET) ||
        (rt->rtr_family == AF_INET6)) {
        memcpy(rt_marker, rt->rtr_prefix, RT_IP_ADDR_SIZE(rt->rtr_family));

        if (rt->rtr_prefix_size) {
            if (cmd_op == SANDESH_OP_GET)
                address_mask(rt->rtr_prefix, rt->rtr_prefix_len, rt->rtr_family);
            inet_ntop(rt->rtr_family, rt->rtr_prefix, addr, sizeof(addr));
            ret = printf("%s/%-2d", addr, rt->rtr_prefix_len);
        }
        for (i = ret; i < 21; i++)
            printf(" ");

        printf("%4d", rt->rtr_replace_plen);

        for (i = 0; i < 8; i++)
            printf(" ");

        memset(flags, 0, sizeof(flags));
        if (rt->rtr_label_flags & VR_RT_LABEL_VALID_FLAG)
            strcat(flags, "L");
        if (rt->rtr_label_flags & VR_RT_ARP_PROXY_FLAG)
            strcat(flags, "P");
        if (rt->rtr_label_flags & VR_RT_ARP_TRAP_FLAG)
            strcat(flags, "T");
        if (rt->rtr_label_flags & VR_RT_ARP_FLOOD_FLAG)
            strcat(flags, "F");

        printf("%5s", flags);

        for (i = 0; i < 6; i++)
            printf(" ");

        if (rt->rtr_label_flags & VR_RT_LABEL_VALID_FLAG)
            printf("%5d", rt->rtr_label);
        else
            printf("%5c", '-');

        for (i = 0; i < 8; i++)
            printf(" ");

        printf("%7d", rt->rtr_nh_id);

        for (i = 0; i < 8; i++)
            printf(" ");

        if (rt->rtr_mac_size) {
            printf("%s(%d)", ether_ntoa((struct ether_addr *)(rt->rtr_mac)),
                    rt->rtr_index);
        } else {
            printf("-");
        }

        printf("\n");
    } else {
        memcpy(rt_marker, rt->rtr_mac, VR_ETHER_ALEN);
        vr_bridge_print_route(rt->rtr_mac, rt->rtr_index,
                rt->rtr_label_flags, rt->rtr_label, rt->rtr_nh_id, 0);
    }

    return;
}

static void
response_process(void *s)
{
    vr_response_common_process((vr_response *)s, &dump_pending);
    return;
}

static void
rt_fill_nl_callbacks()
{
    nl_cb.vr_response_process = response_process;
    nl_cb.vr_route_req_process = route_req_process;
    nl_cb.vr_bridge_table_data_process = bridge_table_data_process;
}


static void
vr_print_rtable_header(unsigned int family, unsigned int vrf)
{
    char addr[INET6_ADDRSTRLEN];

    dump_legend(family);
    switch (family) {
    case AF_INET:
    case AF_INET6:
        printf("vRouter inet%c routing table %d/%d/unicast\n",
                   (family == AF_INET) ? '4' : '6',
                    0, cmd_vrf_id);
        printf("Destination           PPL        Flags        Label         "
                "Nexthop    Stitched MAC(Index)\n");
        break;

    case AF_BRIDGE:
        printf("vRouter bridge table %d/%d\n", 0, cmd_vrf_id);
        printf("Index       DestMac                  Flags           "
                "Label/VNID      Nexthop           Stats\n");
        break;

    default:
        break;
    }

    return;
}

static void
vr_bridge_table_dump(unsigned int vrf)
{
    unsigned int i;
    struct vr_bridge_entry *be;

    for (i = 0; i < vr_bridge_table.bt_num_entries; i++) {
        be = &vr_bridge_table.bt_entries[i];
        if (!(be->be_flags & VR_BE_VALID_FLAG) ||
                (be->be_key.be_vrf_id != vrf))
            continue;
        vr_bridge_print_route(be->be_key.be_mac, i, be->be_flags,
                be->be_label, be->be_nh_id, be->be_packets);
    }

    return;
}

static int
vr_route_op(struct nl_client *cl)
{
    int ret;
    bool dump = false;
    unsigned int flags = 0;
    uint8_t *dst_mac = NULL;
    char addr[INET6_ADDRSTRLEN];

    if (cmd_op == SANDESH_OP_DUMP || cmd_op == SANDESH_OP_GET) {
        vr_print_rtable_header(cmd_family_id, cmd_vrf_id);
    }

    if (cmd_proxy_set)
        flags |= VR_RT_ARP_PROXY_FLAG;

    if (cmd_flood_set)
        flags |= VR_RT_ARP_FLOOD_FLAG;

    if (cmd_trap_set)
        flags |= VR_RT_ARP_TRAP_FLAG;

    if (cmd_dst_mac_set)
        dst_mac = cmd_dst_mac;

op_retry:
    switch (cmd_op) {
    case SANDESH_OP_ADD:
        ret = vr_send_route_add(cl, 0, cmd_vrf_id, cmd_family_id,
                cmd_prefix, cmd_plen, cmd_nh_id, cmd_label, dst_mac,
                cmd_replace_plen, flags | cust_flags);
        break;

    case SANDESH_OP_DUMP:
        if (cmd_family_id == AF_BRIDGE) {
            vr_bridge_table_dump(cmd_vrf_id);
            return 0;
        } else {
            dump = true;
            ret = vr_send_route_dump(cl, 0, cmd_vrf_id, cmd_family_id,
                rt_marker);
        }

        break;

    case SANDESH_OP_DEL:
        ret = vr_send_route_delete(cl, 0, cmd_vrf_id, cmd_family_id,
                cmd_prefix, cmd_plen, cmd_nh_id, cmd_label, cmd_dst_mac,
                cmd_replace_plen, flags);
        break;

    case SANDESH_OP_GET:
        ret = vr_send_route_get(cl, 0, cmd_vrf_id, cmd_family_id,
                cmd_prefix, cmd_plen, cmd_dst_mac);
        break;

    default:
        ret = -EINVAL;
        break;
    }

    if (ret < 0)
        return ret;


    ret = vr_recvmsg(cl, dump);
    if (ret <= 0)
        return ret;

    if (dump_pending)
        goto op_retry;

    return 0;
}

static int
bridge_table_map(vr_bridge_table_data *table)
{
    const char *mmap_error_msg;

    vr_bridge_table.bt_size = table->btable_size;
    vr_bridge_table.bt_num_entries =
        table->btable_size / sizeof(struct vr_bridge_entry);

    mmap_error_msg = vr_table_map(table->btable_dev, VR_MEM_BRIDGE_TABLE_OBJECT,
        table->btable_file_path, table->btable_size, &vr_bridge_table.bt_entries);

    if (mmap_error_msg) {
        printf("%s\n", mmap_error_msg);
        exit(1);
    }

    return 0;
}

static void
bridge_table_data_process(void *s_req)
{
    vr_bridge_table_data *req = (vr_bridge_table_data *)s_req;

    bridge_table_map(req);

    return;
}

static int
vr_bridge_table_setup(struct nl_client *cl)
{
    int ret;

    ret = vr_send_get_bridge_table_data(cl);
    if (!ret)
        return ret;

    ret = vr_recvmsg(cl, false);
    if (ret <= 0)
        return -1;

    return 0;
}

static void
usage_internal()
{
    printf("Usage: c - create\n"
           "       d - delete\n"
           "       b - dump\n"
           "       n <nhop_id> \n"
           "       p <prefix in dotted decimal form> \n"
           "       P <do proxy arp for this route> \n"
           "       F <do arp Flood for this route> \n"
           "       l <prefix_length>\n"
           "       t <label/vnid>\n"
           "       f <family 0 - AF_INET 1 - AF_BRIDGE 2 - AF_INET6 >\n"
           "       e <mac address in : format>\n"
           "       T <trap ARP requests to Agent for this route>\n"
           "       r <replacement route prefix length for delete>\n"
           "       v <vrfid>\n"
           "       x <custom flag in hexa> \n"
           "                               \n"
           "           for inet(6) routes: \n"
           "          VR_RT_LABEL_VALID_FLAG      0x1\n"
           "          VR_RT_ARP_PROXY_FLAG        0x2\n"
           "          VR_RT_ARP_TRAP_FLAG         0x4\n"
           "          VR_RT_ARP_FLOOD_FLAG        0x8\n"
           "\n"
           "           for bridge routes:  \n"
           "          VR_BE_VALID_FLAG            0x01\n"
           "          VR_BE_LABEL_VALID_FLAG      0x02\n"
           "          VR_BE_FLOOD_DHCP_FLAG       0x04\n"
           "\n");
    exit(1);
}

static void
validate_options(void)
{
    unsigned int set = dump_set + family_set + cmd_set + help_set + monitor_set;

    char addr[INET6_ADDRSTRLEN];
    struct ether_addr *eth;

    if (monitor)
        return;

    if (cmd_op < 0)
        goto usage;

    switch (cmd_op) {
    case SANDESH_OP_DUMP:
        if (cmd_vrf_id < 0)
            goto usage;

        if (set > 1 && !family_set)
            goto usage;

        break;

    case SANDESH_OP_DEL:
        if ((cmd_family_id == AF_INET) || (cmd_family_id == AF_INET6)) {

            if (cmd_replace_plen == 0xFFFFFFFF)
                goto usage_internal;

            if (cmd_replace_plen > (RT_IP_ADDR_SIZE(cmd_family_id) * 8)) {
                goto usage_internal;
            }

            if (!cmd_prefix_set || cmd_plen < 0 || cmd_nh_id  < 0 || cmd_vrf_id < 0)
                goto usage_internal;
        } else if (cmd_family_id == AF_BRIDGE) {
            if (!cmd_dst_mac_set || cmd_vrf_id < 0)
                goto usage_internal;
        }

        break;

    case SANDESH_OP_ADD:
        if ((cmd_family_id == AF_INET) || (cmd_family_id == AF_INET6)) {
            if (!cmd_prefix_set || cmd_plen < 0 || cmd_nh_id  < 0 || cmd_vrf_id < 0)
                goto usage_internal;
        } else if (cmd_family_id == AF_BRIDGE) {
            if (!cmd_dst_mac_set || cmd_vrf_id < 0 || cmd_nh_id < 0)
                goto usage_internal;
        }

        break;

    case SANDESH_OP_GET:
        if (cmd_vrf_id < 0 || !cmd_prefix_string)
            goto usage;

        switch (cmd_family_id) {
        case AF_INET:
        case AF_INET6:
            if (cmd_family_id == AF_INET) {
                if (!vr_valid_ipv4_address(cmd_prefix_string))
                    goto usage;
            } else {
                if (!vr_valid_ipv6_address(cmd_prefix_string))
                    goto usage;
            }


            if (inet_pton(cmd_family_id, cmd_prefix_string, cmd_prefix) != 1) {
                printf("%s: inet_pton fails for %s\n", __FUNCTION__, cmd_prefix_string);
                exit(EINVAL);
            }

            if (!cmd_plen_string)
                goto usage;

            cmd_plen = strtoul(cmd_plen_string, NULL, 0);
            address_mask(cmd_prefix, cmd_plen, cmd_family_id);
            printf("Match %s/%u in vRouter inet%c table %u/%u/unicast\n\n",
                    inet_ntop(cmd_family_id, &cmd_prefix, addr, sizeof(addr)),
                    cmd_plen, (cmd_family_id == AF_INET) ? '4' : '6',
                    0, cmd_vrf_id);
            break;

        case AF_BRIDGE:
            eth = ether_aton(cmd_prefix_string);
            if (!eth) {
                printf("%s: ether_aton fails on %s\n",
                        __FUNCTION__, cmd_prefix_string);
                exit(EINVAL);
            }

            memcpy(cmd_dst_mac, eth, sizeof(cmd_dst_mac));
            printf("Match %s in vRouter bridge table %u/%u/unicast\n\n",
                    ether_ntoa((const struct ether_addr *)cmd_dst_mac),
                    0, cmd_vrf_id);
            break;

        default:
            printf("Address family %d not supported\n", cmd_family_id);
            exit(EINVAL);
        }


        break;

    default:
        goto usage_internal;
    }

    return;

usage:
    Usage();
    return;

usage_internal:
    usage_internal();
    return;
}

enum opt_flow_index {
    COMMAND_OPT_INDEX,
    DUMP_OPT_INDEX,
    MONITOR_OPT_INDEX,
    FAMILY_OPT_INDEX,
    GET_OPT_INDEX,
    VRF_OPT_INDEX,
    HELP_OPT_INDEX,
    MAX_OPT_INDEX,
};

static struct option long_options[] = {
    [COMMAND_OPT_INDEX]       = {"cmd",     no_argument,       &cmd_set,     1},
    [DUMP_OPT_INDEX]          = {"dump",    required_argument, &dump_set,    1},
    [MONITOR_OPT_INDEX]       = {"monitor", no_argument,       &monitor_set, 1},
    [FAMILY_OPT_INDEX]        = {"family",  required_argument, &family_set,  1},
    [GET_OPT_INDEX]           = {"get",     required_argument, &get_set,     1},
    [VRF_OPT_INDEX]           = {"vrf",     required_argument, &vrf_set,     1},
    [HELP_OPT_INDEX]          = {"help",    no_argument,       &help_set,    1},
    [MAX_OPT_INDEX]           = { NULL,     0,                 0,            0},
};

static void
Usage(void)
{
    printf("Usage:    rt --dump <vrf_id> [--family <inet|inet6|bridge>]>\n");
    printf("          rt --get <address/plen> --vrf <id> [--family <inet|inet6>]\n");
    printf("          rt --monitor\n");
    printf("          rt --help\n");
    printf("\n");
    printf("--dump    Dumps the routing table corresponding to vrf_id\n");
    printf("--family  Optional family specification to --dump command\n");
    printf("          Specification should be one of \"inet\" or \"bridge\"\n");
    printf("--monitor Watch for netlink broadcasted messages\n");
    printf("--help    Prints this help message\n");

    exit(1);
}

static void
parse_long_opts(int opt_flow_index, char *opt_arg)
{
    errno = 0;
    unsigned int arg_len, tok_len;

    switch (opt_flow_index) {
    case COMMAND_OPT_INDEX:
        usage_internal();
        break;

    case DUMP_OPT_INDEX:
        cmd_op = SANDESH_OP_DUMP;
        cmd_vrf_id = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        break;

    case FAMILY_OPT_INDEX:
        cmd_family_id = family_string_to_id(opt_arg);
        if (cmd_family_id != AF_INET &&
                cmd_family_id != AF_BRIDGE &&
                cmd_family_id != AF_INET6)
            Usage();
        break;

    case GET_OPT_INDEX:
        cmd_op = SANDESH_OP_GET;
        arg_len = strlen(opt_arg);
        cmd_prefix_string = vr_extract_token(opt_arg, '/');
        tok_len = strlen(cmd_prefix_string);
        if (tok_len != arg_len) {
            cmd_plen_string = vr_extract_token(cmd_prefix_string + tok_len + 1, '\0');
        }

        break;

    case VRF_OPT_INDEX:
        cmd_vrf_id = strtoul(opt_arg, NULL, 0);
        break;

    case MONITOR_OPT_INDEX:
        monitor = 1;
            break;

    case HELP_OPT_INDEX:
    default:
        Usage();
    }

    return;
}

int
main(int argc, char *argv[])
{
    int ret;
    int opt;
    int option_index;
    struct ether_addr *cmd_eth;

    rt_fill_nl_callbacks();

    cmd_nh_id = -255;
    cmd_label = -1;
    cmd_family_id = AF_INET;

    while ((opt = getopt_long(argc, argv, "TcdbmPn:p:l:v:t:s:e:f:r:Fx:",
                    long_options, &option_index)) >= 0) {
            switch (opt) {
            case 'c':
                if (cmd_op >= 0) {
                    usage_internal();
                }
                cmd_op = SANDESH_OP_ADD;
                break;

            case 'd':
                if (cmd_op >= 0) {
                    usage_internal();
                }
                cmd_op = SANDESH_OP_DEL;
                break;

            case 'b':
                if (cmd_op >= 0) {
                    usage_internal();
                }
                cmd_op = SANDESH_OP_DUMP;
                break;

            case 'v':
                cmd_vrf_id = atoi(optarg);
                break;

            case 'n':
                cmd_nh_id = atoi(optarg);
                break;

            case 'p':
                /*
                 * Try parsing for AF_INET first, if not try AF_INET6
                 */
                if (!inet_pton(AF_INET, optarg, cmd_prefix))
                    inet_pton(AF_INET6, optarg, cmd_prefix);
                cmd_prefix_set = 1;
                break;

            case 'l':
                cmd_plen = atoi(optarg);
                break;

            case 'r':
                cmd_replace_plen = atoi(optarg);
                break;

            case 't':
                cmd_label = atoi(optarg);
                break;

            case 's':
                /*
                 * Try parsing for AF_INET first, if not try AF_INET6
                 */
                if (!inet_pton(AF_INET, optarg, cmd_src))
                    inet_pton(AF_INET6, optarg, cmd_src);
                break;

            case 'f':
                cmd_family_id = atoi(optarg);
                if (cmd_family_id == 0) {
                    cmd_family_id = AF_INET;
                } else if (cmd_family_id == 1) {
                    cmd_family_id = AF_BRIDGE;
                } else {
                    cmd_family_id = AF_INET6;
                }

                break;

            case 'e':
                cmd_eth = ether_aton(optarg);
                if (cmd_eth)
                    memcpy(cmd_dst_mac, cmd_eth, 6);
                cmd_dst_mac_set = 1;
                break;

            case 'P':
                cmd_proxy_set = true;
                break;

            case 'F':
                cmd_flood_set = true;
                break;

            case 'T':
                cmd_trap_set = true;
                break;

            case 'x':
                cust_flags = strtoul(optarg, NULL, 16);
                break;
            case 0:
                parse_long_opts(option_index, optarg);
                break;

            case '?':
            default:
                Usage();
                break;
        }
    }

    validate_options();
    cl = vr_get_nl_client(VR_NETLINK_PROTO_DEFAULT);
    if (!cl) {
        exit(1);
    }

    if (monitor)
        while (1) {
            ret = vr_recvmsg_waitall(cl, false);
            if (ret == -1)
                exit(1);
        }

    if (cmd_family_id == AF_BRIDGE) {
        if (cmd_op == SANDESH_OP_DUMP || cmd_op == SANDESH_OP_GET) {
            ret = vr_bridge_table_setup(cl);
            if (ret) {
                exit(1);
            }
        }
    }

    vr_route_op(cl);
    return 0;
}
