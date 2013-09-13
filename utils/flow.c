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
#include <malloc.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>

#include <asm/types.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>

#include <net/if.h>
#ifdef __KERNEL__
#include <netinet/ether.h>
#endif

#include "vr_types.h"
#include "vr_flow.h"
#include "vr_mirror.h"
#include "vr_genetlink.h"
#include "nl_util.h"

#define TABLE_FLAG_VALID        0x1
#define MEM_DEV                 "/dev/flow"

static int snat_set, dnat_set, spat_set, dpat_set, dvrf_set, mir_set;
static struct in_addr snat, dnat;
static unsigned short spat, dpat, dvrf;
static int flow_index, list, flow_cmd, mirror = -1;

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

static void
dump_table(struct flow_table *ft)
{
    unsigned int i, j, fi, need_flag_print = 0;
    struct vr_flow_entry *fe;
    char action, flag_string[sizeof(fe->fe_flags) * 8 + 32];
    struct in_addr in_src, in_dest;

    printf("Flow table\n\n");
    printf(" Index              Source:Port           Destination:Port    \tProto(V)\n");
    printf("-----------------------------------------------------------------");
    printf("--------\n");
    for (i = 0; i < ft->ft_num_entries; i++) {
        bzero(flag_string, sizeof(flag_string));
        need_flag_print = 0;
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
                    fe->fe_key.key_vrf_id);

            if (fe->fe_rflow >= 0 && fe->fe_flags & VR_FLOW_FLAG_VRFT)
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
                    }

                break;

            default:
                action = 'U';
            }

            printf("\t\t\t(");
            printf("Action:%c", action);
            if (need_flag_print)
                printf("(%s)", flag_string);

            printf(", ");
            if (fe->fe_ecmp_nh_index >= 0)
                printf("E:%d, ", fe->fe_ecmp_nh_index);

            printf(" Statistics:%d/%d", fe->fe_stats.flow_packets,
                    fe->fe_stats.flow_bytes);
            if (fe->fe_flags & VR_FLOW_FLAG_MIRROR) {
                printf(" Mirror Index :");
                if (fe->fe_mirror_id < VR_MAX_MIRROR_INDICES)
                    printf(" %d", fe->fe_mirror_id);
                if (fe->fe_sec_mirror_id < VR_MAX_MIRROR_INDICES)
                    printf(", %d", fe->fe_sec_mirror_id);
            }
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
    flow_req.fr_flow_vrf = fe->fe_key.key_vrf_id;

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

    case 'n':
        flow_req.fr_rindex = -1;
        flow_req.fr_action = VR_FLOW_ACTION_NAT;

        flow_req.fr_rflow_dip = fe->fe_key.key_src_ip;
        if (snat_set) {
            flow_req.fr_flags |= VR_FLOW_FLAG_SNAT;
            flow_req.fr_rflow_dip = snat.s_addr;
        }

        flow_req.fr_rflow_sip = fe->fe_key.key_dest_ip;
        if (dnat_set) {
            flow_req.fr_flags |= VR_FLOW_FLAG_DNAT;
            flow_req.fr_rflow_sip = dnat.s_addr;
        }

        flow_req.fr_rflow_dport = fe->fe_key.key_src_port;
        if (spat_set) {
            flow_req.fr_flags |= VR_FLOW_FLAG_SPAT;
            flow_req.fr_rflow_dport = spat;
        }

        flow_req.fr_rflow_sport = fe->fe_key.key_dst_port;
        if (dpat_set) {
            flow_req.fr_flags |= VR_FLOW_FLAG_DPAT;
            flow_req.fr_rflow_sport = dpat;
        }

        flow_req.fr_rflow_vrf = fe->fe_key.key_vrf_id;
        if (dvrf_set) {
            flow_req.fr_flags |= VR_FLOW_FLAG_VRFT;
            flow_req.fr_flow_dvrf = dvrf;
            flow_req.fr_rflow_vrf = dvrf;
        }

        flow_req.fr_rflow_proto = fe->fe_key.key_proto;

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
    printf("flow [-f flow_index][-d flow_index][-i flow_index]\n");
    printf("     [-n flow_index [--snat=x.x.x.x] [--dnat=x.x.x.x]");
    printf("[--spat=sport][--dpat=dport]] \n");
    printf("     [--mirror=mirror table index]\n");
    printf("     [-l]\n");
    printf("\n");

    printf("-f <flow_index>\t Set forward action for flow at flow_index <flow_index>\n");
    printf("-d <flow_index>\t Set drop action for flow at flow_index <flow_index>\n");
    printf("-i <flow_index>\t Invalidate flow at flow_index <flow_index>\n");
    printf("-n <flow_index>\t Set NAT action for flow at flow_index <flow_index>\n");
    printf("\t\t --snat=source IP to change to,\n");
    printf("\t\t --dnat=destination IP to change to,\n");
    printf("\t\t --spat=source Port to change to,\n");
    printf("\t\t --dpat=destination Port to change to,\n");
    printf("\t\t --dvrf=destination VRF to send the packet to,\n");
    printf("--mirror\tmirror index to mirror to\n");
    printf("-l\t\t List all flows\n");

    exit(-EINVAL);
}

enum opt_flow_index {
    SNAT_OPT_INDEX,
    DNAT_OPT_INDEX,
    SPAT_OPT_INDEX,
    DPAT_OPT_INDEX,
    DVRF_OPT_INDEX,
    MIRROR_OPT_INDEX,
    MAX_OPT_INDEX
};

static struct option long_options[] = {
    [SNAT_OPT_INDEX]    = {"snat", required_argument, &snat_set, 1},
    [DNAT_OPT_INDEX]    = {"dnat", required_argument, &dnat_set, 1},
    [SPAT_OPT_INDEX]    = {"spat", required_argument, &spat_set, 1},
    [DPAT_OPT_INDEX]    = {"dpat", required_argument, &dpat_set, 1},
    [DVRF_OPT_INDEX]    = {"dvrf", required_argument, &dvrf_set, 1},
    [MIRROR_OPT_INDEX]  = {"mirror", required_argument, &mir_set, 1},
    [MAX_OPT_INDEX]     = { NULL,  0,                 0        , 0}
};

static void
validate_options(void)
{
    if (!flow_index && !list)
        Usage();

    switch (flow_cmd) {
    case 'n':
        if (!snat_set && !dnat_set && !spat_set && !dpat_set)
            Usage();
        break;

    default:
        if (snat_set || dnat_set || spat_set || dpat_set)
            Usage();
        break;
    }

    return;
}

static void
parse_long_opts(int opt_flow_index, char *opt_arg)
{
    int ret;

    errno = 0;
    switch (opt_flow_index) {

    case SNAT_OPT_INDEX:
        ret = inet_aton(opt_arg, &snat);
        break;

    case DNAT_OPT_INDEX:
        ret = inet_aton(opt_arg, &dnat);
        break;

    case SPAT_OPT_INDEX:
        ret = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        spat = htons(ret);
        break;

    case DPAT_OPT_INDEX:
        ret = strtoul(opt_arg, NULL, 0);
        if (errno)
            Usage();
        dpat = htons(ret);
        break;

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

    while ((opt = getopt_long(argc, argv, "d:f:i:ln:",
                    long_options, &option_index)) >= 0) {
        switch (opt) {
        case 'f':
        case 'd':
        case 'n':
        case 'i':
            flow_cmd = opt;
            flow_index = strtoul(optarg, NULL, 0);
            break;

        case 'l':
            list = 1;
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
    else
        flow_validate(flow_index, flow_cmd);

    return 0;
}
