/*
 * flow.c -- flow handling utility
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#if defined(__linux__)
#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>
#endif

#include <net/if.h>
#ifdef __KERNEL__
#include <netinet/ether.h>
#endif

#include "vr_types.h"
#include "vr_flow.h"
#include "vr_mirror.h"
#include "vr_genetlink.h"
#include "nl_util.h"
#include "vr_os.h"

#define TABLE_FLAG_VALID        0x1
#define MEM_DEV                 "/dev/flow"

static int dvrf_set, mir_set, help_set;
static unsigned short dvrf;
static int flow_index, list, flow_cmd, mirror = -1;
static int rate;
static int stats;

struct flow_table {
    struct vr_flow_entry *ft_entries;
    u_int64_t ft_entries_p;
    u_int64_t ft_span;
    unsigned int ft_num_entries;
    unsigned int ft_flags;
} main_table;

int mem_fd;
struct nl_client *cl;
vr_flow_req flow_req;


struct vr_flow_entry *
flow_get(unsigned int flow_index)
{
    return &main_table.ft_entries[flow_index];
}

const char *
flow_get_drop_reason(uint8_t drop_code)
{
    switch (drop_code) {
    case VR_FLOW_DR_UNKNOWN:
        return "Unknown";
    case VR_FLOW_DR_UNAVIALABLE_INTF:
        return "IntfErr";
    case VR_FLOW_DR_IPv4_FWD_DIS:
        return "Ipv4Dis";
    case VR_FLOW_DR_UNAVAILABLE_VRF:
        return "VrfErr";
    case VR_FLOW_DR_NO_SRC_ROUTE:
        return "NoSrcRt";
    case VR_FLOW_DR_NO_DST_ROUTE:
        return "NoDstRt";
    case VR_FLOW_DR_AUDIT_ENTRY:
        return "Audit";
    case VR_FLOW_DR_VRF_CHANGE:
        return "VrfChange";
    case VR_FLOW_DR_NO_REVERSE_FLOW:
        return "NoRevFlow";
    case VR_FLOW_DR_REVERSE_FLOW_CHANGE:
        return "RevFlowChng";
    case VR_FLOW_DR_NAT_CHANGE:
        return "NatChng";
    case VR_FLOW_DR_FLOW_LIMIT:
        return "FlowLim";
    case VR_FLOW_DR_LINKLOCAL_SRC_NAT:
        return "LinkSrcNatErr";
    case VR_FLOW_DR_POLICY:
        return "Policy";
    case VR_FLOW_DR_OUT_POLICY:
        return "OutPolicy";
    case VR_FLOW_DR_SG:
        return "SG";
    case VR_FLOW_DR_OUT_SG:
        return "OutSG";
    case VR_FLOW_DR_REVERSE_SG:
        return "RevSG";
    case VR_FLOW_DR_REVERSE_OUT_SG:
        return "RevOutSG";
    default:
        break;
    }
    return NULL;
}

static void
dump_table(struct flow_table *ft)
{
    unsigned int i, j, fi, need_flag_print = 0;
    struct vr_flow_entry *fe;
    char action, flag_string[sizeof(fe->fe_flags) * 8 + 32];
    unsigned int need_drop_reason = 0;
    const char *drop_reason = NULL;
    struct in_addr in_src, in_dest;

    printf("Flow table\n\n");
    printf(" Index              Source:Port           Destination:Port    \tProto(V)\n");
    printf("-----------------------------------------------------------------");
    printf("--------\n");
    for (i = 0; i < ft->ft_num_entries; i++) {
        bzero(flag_string, sizeof(flag_string));
        need_flag_print = 0;
        need_drop_reason = 0;
        fe = (struct vr_flow_entry *)((char *)ft->ft_entries + (i * sizeof(*fe)));
        if (fe->fe_flags & VR_FLOW_FLAG_ACTIVE) {
            in_src.s_addr = fe->fe_key.key_src_ip;
            in_dest.s_addr = fe->fe_key.key_dest_ip;
            printf("%6d", i);
            if (fe->fe_rflow >= 0)
                printf("<=>%-6d", fe->fe_rflow);
            else
                printf("         ");

            printf("   %12s:%-5d    ", inet_ntoa(in_src),
                    ntohs(fe->fe_key.key_src_port));
            printf("%16s:%-5d    %d (%d",
                    inet_ntoa(in_dest),
                    ntohs(fe->fe_key.key_dst_port),
                    fe->fe_key.key_proto,
                    fe->fe_vrf);

            if (fe->fe_flags & VR_FLOW_FLAG_VRFT)
                printf("->%d", fe->fe_dvrf);

            printf(")\n");

            switch (fe->fe_action) {
            case VR_FLOW_ACTION_HOLD:
                action = 'H';
                break;

            case VR_FLOW_ACTION_FORWARD:
                action = 'F';
                break;

            case VR_FLOW_ACTION_DROP:
                action = 'D';
                need_drop_reason = 1;
                drop_reason = flow_get_drop_reason(fe->fe_drop_reason);
                break;

            case VR_FLOW_ACTION_NAT:
                action = 'N';
                need_flag_print = 1;
                fi = 0;
                for (j = 0; (j < (sizeof(fe->fe_flags) * 8)) &&
                        fi < sizeof(flag_string); j++)
                    switch ((1 << j) & fe->fe_flags) {
                    case VR_FLOW_FLAG_SNAT:
                        flag_string[fi++] = 'S';
                        break;
                    case VR_FLOW_FLAG_DNAT:
                        flag_string[fi++] = 'D';
                        break;
                    case VR_FLOW_FLAG_SPAT:
                        flag_string[fi++] = 'P';
                        flag_string[fi++] = 's';
                        break;
                    case VR_FLOW_FLAG_DPAT:
                        flag_string[fi++] = 'P';
                        flag_string[fi++] = 'd';
                        break;
                    case VR_FLOW_FLAG_LINK_LOCAL:
                        flag_string[fi++] = 'L';
                    }

                break;

            default:
                action = 'U';
            }

            printf("\t(");
            printf("K(nh):%u, ", fe->fe_key.key_nh_id);
            printf("Action:%c", action);
            if (need_flag_print)
                printf("(%s)", flag_string);
            if (need_drop_reason) {
                if (drop_reason != NULL)
                    printf("(%s)", drop_reason);
                else
                    printf("(%u)", fe->fe_drop_reason);
            }

            printf(", ");
            if (fe->fe_ecmp_nh_index >= 0)
                printf("E:%d, ", fe->fe_ecmp_nh_index);

            printf("S(nh):%u, ", fe->fe_src_nh_index);
            printf(" Statistics:%u/%u", fe->fe_stats.flow_packets,
                    fe->fe_stats.flow_bytes);
            if (fe->fe_flags & VR_FLOW_FLAG_MIRROR) {
                printf(" Mirror Index :");
                if (fe->fe_mirror_id < VR_MAX_MIRROR_INDICES)
                    printf(" %d", fe->fe_mirror_id);
                if (fe->fe_sec_mirror_id < VR_MAX_MIRROR_INDICES)
                    printf(", %d", fe->fe_sec_mirror_id);
            }
            printf(" UdpSrcPort %d", fe->fe_udp_src_port);
            printf(")\n\n");
        }
    }

    return;
}

static void
flow_list(void)
{
    dump_table(&main_table);
    return;
}

static void
flow_stats(void)
{
    struct flow_table *ft = &main_table;
    unsigned int i;
    struct vr_flow_entry *fe;
    struct timeval now;
    struct timeval last_time;
    int active_entries = 0;
    int hold_entries = 0;
    int prev_active_entries = 0;
    int prev_hold_entries = 0;
    int total_entries = 0;
    int prev_total_entries = 0;
    int diff_ms;
    int rate;
    int avg_setup_rate = 0;
    int avg_teardown_rate = 0;
    uint64_t setup_time = 0;
    uint64_t teardown_time = 0;
    int total_rate;
    int flow_action_drop = 0;
    int flow_action_fwd = 0;
    int flow_action_nat = 0;

    gettimeofday(&last_time, NULL);
    while (1) {
        active_entries = 0;
        total_entries = 0;
        hold_entries = 0;
        flow_action_drop = 0;
        flow_action_fwd = 0;
        flow_action_nat = 0;
        usleep(500000);
        for (i = 0; i < ft->ft_num_entries; i++) {
            fe = (struct vr_flow_entry *)((char *)ft->ft_entries +
                                          (i * sizeof(*fe)));
            if (fe->fe_flags & VR_FLOW_FLAG_ACTIVE) {
                total_entries++;
                if (fe->fe_action != VR_FLOW_ACTION_HOLD) {
                    active_entries++;
                } else {
                    hold_entries++;
                }
                if (fe->fe_action == VR_FLOW_ACTION_DROP) {
                    flow_action_drop++;
                } else if (fe->fe_action == VR_FLOW_ACTION_FORWARD) {
                    flow_action_fwd++;
                } else if (fe->fe_action == VR_FLOW_ACTION_NAT) {
                    flow_action_nat++;
                }
            }
        }
        gettimeofday(&now, NULL);
        /* calc time difference and rate */
        diff_ms = (now.tv_sec - last_time.tv_sec) * 1000;
        diff_ms += (now.tv_usec - last_time.tv_usec) / 1000;
        assert(diff_ms > 0 );
        rate = (active_entries - prev_active_entries) * 1000;
        rate /= diff_ms;
        total_rate = (total_entries - prev_total_entries) * 1000;
        total_rate /= diff_ms;
        if (rate != 0 || total_rate != 0) {
            if (rate < -1000) {
                avg_teardown_rate = avg_teardown_rate * teardown_time -
                    (active_entries - prev_active_entries) * 1000;
                teardown_time += diff_ms;
                avg_teardown_rate /= teardown_time;
            }

            if (rate > 1000) {
                avg_setup_rate = avg_setup_rate * setup_time +
                    (active_entries - prev_active_entries) * 1000;
                setup_time += diff_ms;
                avg_setup_rate /= setup_time;
            }
        }

        system("clear");
        struct tm *tm;
        char fmt[64], buf[64];
        if((tm = localtime(&now.tv_sec)) != NULL)
        {
            strftime(fmt, sizeof fmt, "%Y-%m-%d %H:%M:%S %z", tm);
            snprintf(buf, sizeof buf, fmt, now.tv_usec);
            printf("%s\n", buf); 
        }

        printf("Flow Statistics\n");
        printf("---------------\n");
        printf("    Total  Entries  --- Total = %7d, new = %7d \n",
                total_entries, (total_entries - prev_total_entries));
        printf("    Active Entries  --- Total = %7d, new = %7d \n",
                active_entries, (active_entries - prev_active_entries));
        printf("    Hold   Entries  --- Total = %7d, new = %7d \n",
                hold_entries, (hold_entries - prev_hold_entries));
        printf("    Fwd flow Entries  - Total = %7d\n", flow_action_fwd);
        printf("    drop flow Entries - Total = %7d\n", flow_action_drop);
        printf("    NAT flow Entries  - Total = %7d\n\n", flow_action_nat);
        printf("    Rate of change of Active Entries\n");
        printf("    --------------------------------\n");
        printf("        current rate      = %8d\n", rate);
        printf("        Avg setup rate    = %8d\n", avg_setup_rate);
        printf("        Avg teardown rate = %8d\n", avg_teardown_rate);
        printf("    Rate of change of Flow Entries\n");
        printf("    ------------------------------\n");
        printf("        current rate      = %8d\n", total_rate);

        last_time = now;
        prev_active_entries = active_entries;
        prev_total_entries = total_entries;
        prev_hold_entries = hold_entries;
    }
}

static void
flow_rate(void)
{
    struct flow_table *ft = &main_table;
    unsigned int i;
    struct vr_flow_entry *fe;
    struct timeval now;
    struct timeval last_time;
    int active_entries = 0;
    int prev_active_entries = 0;
    int total_entries = 0;
    int prev_total_entries = 0;
    int diff_ms;
    int rate;
    int total_rate;

    gettimeofday(&last_time, NULL);
    while (1) {
        active_entries = 0;
        total_entries = 0;
        usleep(500000);
        for (i = 0; i < ft->ft_num_entries; i++) {
            fe = (struct vr_flow_entry *)((char *)ft->ft_entries + (i * sizeof(*fe)));
            if (fe->fe_flags & VR_FLOW_FLAG_ACTIVE) {
                total_entries++;
                if (fe->fe_action != VR_FLOW_ACTION_HOLD)
                    active_entries++;
            }
        }
        gettimeofday(&now, NULL);
        /* calc time difference and rate */
        diff_ms = (now.tv_sec - last_time.tv_sec) * 1000;
        diff_ms += (now.tv_usec - last_time.tv_usec) / 1000;
        assert(diff_ms > 0 );
        rate = (active_entries - prev_active_entries) * 1000;
        rate /= diff_ms;
        total_rate = (total_entries - prev_total_entries) * 1000;
        total_rate /= diff_ms;
        if (rate != 0 || total_rate != 0) {
            printf("New = %4d, Flow setup rate = %4d flows/sec, ",
                   (active_entries - prev_active_entries), rate);
            printf("Flow rate = %4d flows/sec, for last %4d ms\n", total_rate, diff_ms);
            fflush(stdout);
        }

        last_time = now;
        prev_active_entries = active_entries;
        prev_total_entries = total_entries;
    }
}

void
vr_response_process(void *sresp)
{
    vr_response *resp = (vr_response *)sresp;

    if (resp->resp_code < 0)
        printf("%s\n", strerror(-resp->resp_code));

    return;
}

int
flow_table_map(vr_flow_req *req)
{
    int ret;
    struct flow_table *ft = &main_table;

    if (req->fr_ftable_dev < 0)
        exit(ENODEV);

    ret = mknod(MEM_DEV, S_IFCHR | O_RDWR,
            makedev(req->fr_ftable_dev, req->fr_rid));
    if (ret && errno != EEXIST) {
        perror(MEM_DEV);
        exit(errno);
    }

    mem_fd = open(MEM_DEV, O_RDONLY | O_SYNC);
    if (mem_fd <= 0) {
        perror(MEM_DEV);
        exit(errno);
    }

    ft->ft_entries = (struct vr_flow_entry *)mmap(NULL, req->fr_ftable_size,
            PROT_READ, MAP_SHARED, mem_fd, 0);
    if (ft->ft_entries == MAP_FAILED) {
        printf("flow table: %s\n", strerror(errno));
        exit(errno);
    }

    ft->ft_span = req->fr_ftable_size;
    ft->ft_num_entries = ft->ft_span / sizeof(struct vr_flow_entry);
    return ft->ft_num_entries;
}



void
vr_flow_req_process(void *sreq)
{
    vr_flow_req *req = (vr_flow_req *)sreq;

    switch (req->fr_op) {
    case FLOW_OP_FLOW_TABLE_GET:
        if (flow_table_map(req) <= 0)
            return;

        break;

    default:
        break;
    }

    return;
}

static int
make_flow_req(vr_flow_req *req)
{
    int ret, attr_len, error;
    struct nl_response *resp;

    ret = nl_build_nlh(cl, cl->cl_genl_family_id, NLM_F_REQUEST);
    if (ret)
        return ret;

    ret = nl_build_genlh(cl, SANDESH_REQUEST, 0);
    if (ret)
        return ret;

    attr_len = nl_get_attr_hdr_size();

    error = 0;
    ret = sandesh_encode(req, "vr_flow_req", vr_find_sandesh_info,
                             (nl_get_buf_ptr(cl) + attr_len),
                             (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }

    nl_build_attr(cl, ret, NL_ATTR_VR_MESSAGE_PROTOCOL);
    nl_update_nlh(cl);
    ret = nl_sendmsg(cl);
    if (ret <= 0)
        return ret;

    while ((ret = nl_recvmsg(cl)) > 0) {
        resp = nl_parse_reply(cl);
        if (resp->nl_op == SANDESH_REQUEST) {
            sandesh_decode(resp->nl_data, resp->nl_len, vr_find_sandesh_info, &ret);
        }
    }

    if (errno == EAGAIN || errno == EWOULDBLOCK)
        ret = 0;

    return ret;
}

int
flow_table_get(void)
{
    /* get the kernel's view of the flow table */
    memset(&flow_req, 0, sizeof(flow_req));
    flow_req.fr_op = FLOW_OP_FLOW_TABLE_GET;

    return make_flow_req(&flow_req);
}

static int
flow_table_setup(void)
{
    int ret;

    cl = nl_register_client();
    if (!cl)
        return -ENOMEM;

    ret = nl_socket(cl, NETLINK_GENERIC);
    if (ret <= 0)
        return ret;

    ret = vrouter_get_family_id(cl);
    if (ret <= 0)
        return ret;

    return ret;
}

void
flow_validate(int flow_index, char action)
{
    struct vr_flow_entry *fe;

    memset(&flow_req, 0, sizeof(flow_req));

    fe = flow_get(flow_index);

    flow_req.fr_op = FLOW_OP_FLOW_SET;
    flow_req.fr_index = flow_index;
    flow_req.fr_flags = VR_FLOW_FLAG_ACTIVE;
    flow_req.fr_flow_sip = fe->fe_key.key_src_ip;
    flow_req.fr_flow_dip = fe->fe_key.key_dest_ip;
    flow_req.fr_flow_proto = fe->fe_key.key_proto;
    flow_req.fr_flow_sport = fe->fe_key.key_src_port;
    flow_req.fr_flow_dport = fe->fe_key.key_dst_port;
    flow_req.fr_flow_nh_id = fe->fe_key.key_nh_id;

    switch (action) {
    case 'd':
        flow_req.fr_action = VR_FLOW_ACTION_DROP;
        break;

    case 'f':
        flow_req.fr_action = VR_FLOW_ACTION_FORWARD;
        break;

    case 'i':
        flow_req.fr_flags = VR_FLOW_FLAG_ACTIVE ^ VR_FLOW_FLAG_ACTIVE;
        flow_req.fr_action = VR_FLOW_ACTION_DROP;
        break;

    default:
        return;
    }

    if (mirror >= 0) {
        flow_req.fr_mir_id = mirror;
        flow_req.fr_flags |= VR_FLOW_FLAG_MIRROR;
    } else
        flow_req.fr_flags &= ~VR_FLOW_FLAG_MIRROR;


    make_flow_req(&flow_req);
    return;
}

static void
Usage(void)
{
    printf("Usage:flow [-f flow_index]\n");
    printf("           [-d flow_index]\n");
    printf("           [-i flow_index]\n");
    printf("           [--mirror=mirror table index]\n");
    printf("           [-l]\n");
    printf("           [-r]\n");
    printf("           [-s]\n");
    printf("\n");

    printf("-f <flow_index>\t Set forward action for flow at flow_index <flow_index>\n");
    printf("-d <flow_index>\t Set drop action for flow at flow_index <flow_index>\n");
    printf("-i <flow_index>\t Invalidate flow at flow_index <flow_index>\n");
    printf("--mirror\t mirror index to mirror to\n");
    printf("-l\t\t List all flows\n");
    printf("-r\t\t Start dumping flow setup rate\n");
    printf("-s\t\t Start dumping flow stats\n");
    printf("--help\t\t Print this help\n");

    exit(-EINVAL);
}

enum opt_flow_index {
    DVRF_OPT_INDEX,
    MIRROR_OPT_INDEX,
    HELP_OPT_INDEX,
    MAX_OPT_INDEX
};

static struct option long_options[] = {
    [DVRF_OPT_INDEX]    = {"dvrf",   required_argument, &dvrf_set, 1},
    [MIRROR_OPT_INDEX]  = {"mirror", required_argument, &mir_set,  1},
    [HELP_OPT_INDEX]    = {"help",   no_argument,       &help_set, 1},
    [MAX_OPT_INDEX]     = { NULL,    0,                 0,         0}
};

static void
validate_options(void)
{
    if (!flow_index && !list && !rate && !stats)
        Usage();

    return;
}

static void
parse_long_opts(int opt_flow_index, char *opt_arg)
{
    errno = 0;
    switch (opt_flow_index) {
    case DVRF_OPT_INDEX:
        dvrf = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        break;

    case MIRROR_OPT_INDEX:
        mirror = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
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
    char opt;
    int ret;
    int option_index;

    while ((opt = getopt_long(argc, argv, "d:f:i:lrs",
                    long_options, &option_index)) >= 0) {
        switch (opt) {
        case 'f':
        case 'd':
        case 'i':
            flow_cmd = opt;
            flow_index = strtoul(optarg, NULL, 0);
            break;

        case 'l':
            list = 1;
            break;

        case 'r':
            rate = 1;
            break;
        case 's':
            stats = 1;
            break;
        case 0:
            parse_long_opts(option_index, optarg);
            break;

        default:
            Usage();
        }
    }

    validate_options();

    ret = flow_table_setup();
    if (ret < 0)
        return ret;

    ret = flow_table_get();
    if (ret < 0)
        return ret;

    if (list)
        flow_list();
    else if (rate)
        flow_rate();
    else if (stats)
        flow_stats();
    else
        flow_validate(flow_index, flow_cmd);

    return 0;
}
