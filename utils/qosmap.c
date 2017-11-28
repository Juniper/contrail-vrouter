/*
 * qosmap.c -- utility to set and get qos mappings
 *
 * Copyright (c) 2016, Juniper Networks, Inc.
 * All rights reserved
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>

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
#include <linux/dcbnl.h>
#endif

#include <net/if.h>
#if defined(__linux__)
#include <netinet/ether.h>
#endif

#include "vr_types.h"
#include "vr_qos.h"
#include "vr_flow.h"
#include "vr_mirror.h"
#include "vr_genetlink.h"
#include "nl_util.h"
#include "vr_os.h"
#include "ini_parser.h"
#include "vr_packet.h"

#define DCBX_MODE_CEE       1
#define DCBX_MODE_IEEE      2


static bool dump_pending = false;
static int marker = -1;

static unsigned int help_set, dump_fc_set, dump_qos_set;
static unsigned int get_fc_set, set_fc_set, fc_set;
static unsigned int get_qos_set, set_qos_set, delete_qos_set;
static unsigned int dscp_set, mpls_qos_set, dotonep_set, queue_set;
static unsigned int set_queue_set, pg_set, pg_bw_set, strict_set;
static unsigned int get_queue_set, tc_set, dcbx_set, default_tc;

static uint8_t dotonep, dscp, mpls_qos, fc, queue;
static uint8_t dcbx_mode, dcb_enable;
static unsigned int qos_index, if_index;
static uint8_t ifname[IFNAMSIZ];

struct priority priority_map;
struct nl_client *cl;

static void
dump_priority(void)
{
    unsigned int i;
    unsigned char ifname[IF_NAMESIZE];
    uint8_t *dcbx_str;

    printf("Priority Operation\n");
    printf("Interface:                  %5s\n", if_indextoname(if_index, ifname));
    if (dcbx_mode & DCB_CAP_DCBX_VER_IEEE) {
        dcbx_str = "IEEE";
    } else if (dcbx_mode & DCB_CAP_DCBX_VER_CEE) {
        dcbx_str = "CEE";
    } else {
        dcbx_str = "Unknown DCBX mode";
    }

    printf("DCBX:                       %5s\n", dcbx_str);
    printf("DCB State:                  %5s\n", dcb_enable ? "Enabled" : "Disabled");

    printf("\n");
    printf("                            ");
    for (i = 0; i < NUM_TC; i++) {
        printf("   P%u", i);
    }
    printf("\n");
    printf("Traffic Class:              ");
    for (i = 0; i < NUM_TC; i++) {
        printf("%5u", priority_map.prio_to_tc[i]);
    }
    printf("\n");

    printf("\n");
    printf("                            ");
    for (i = 0; i < NUM_TC; i++) {
        printf("  TC%u", i);
    }
    printf("\n");

    printf("Priority Group:             ");
    for (i = 0; i < NUM_PG; i++) {
        printf("%5u", priority_map.tc_to_group[i]);
    }
    printf("\n");

    printf("\n");
    printf("                            ");
    for (i = 0; i < NUM_PG; i++) {
        printf("  PG%u", i);
    }
    printf("\n");
    printf("Priority Group Bandwidth:   ");
    for (i = 0; i < NUM_PG; i++) {
        printf("%5u", priority_map.prio_group_bw[i]);
    }
    printf("\n");
    printf("Strictness:                 ");
    for (i = 0; i < NUM_TC; i++) {
        printf("%5u", (priority_map.tc_strictness & (1 << i)) ? 1 : 0);
    }
    printf("\n");

    return;
}

static void
fc_map_req_process(void *s)
{
    unsigned int i;
    vr_fc_map_req *req = (vr_fc_map_req *)s;

    if (marker == -1) {
        printf("Forwarding Class Map %d\n", req->fmr_rid);
        printf(" FC            DSCP  EXP  .1p    Queue\n");
    }

    for (i = 0; i < req->fmr_id_size; i++) {
        printf("%3u        %8u  %3u  %3u %8u\n",
                req->fmr_id[i], req->fmr_dscp[i], req->fmr_mpls_qos[i],
                req->fmr_dotonep[i], req->fmr_queue_id[i]);
    }

    if (i > 0) {
        marker = (unsigned int)(req->fmr_id[i - 1]);
    }

    return;
}

static void
qos_map_req_process(void *s)
{
    unsigned int i;
    vr_qos_map_req *req = (vr_qos_map_req *)s;

    printf("QOS Map %d/%d\n", req->qmr_rid, req->qmr_id);
    if (req->qmr_dscp_size) {
        printf("    DSCP              FC\n");
        for (i = 0; i < req->qmr_dscp_size; i++) {
            if (req->qmr_dscp_fc_id[i])
                printf("%8u        %8u\n", req->qmr_dscp[i],
                        req->qmr_dscp_fc_id[i]);
        }
        printf("\n");
    }

    if (req->qmr_mpls_qos_size) {
        printf("     EXP              FC\n");
        for (i = 0; i < req->qmr_mpls_qos_size; i++) {
            if (req->qmr_mpls_qos_fc_id[i])
                printf("%8u        %8u\n", req->qmr_mpls_qos[i],
                        req->qmr_mpls_qos_fc_id[i]);
        }
        printf("\n");
    }

    if (req->qmr_dotonep_size) {
        printf(" DOTONEP              FC\n");
        for (i = 0; i < req->qmr_dotonep_size; i++) {
            if (req->qmr_dotonep_fc_id[i])
                printf("%8u        %8u\n", req->qmr_dotonep[i],
                        req->qmr_dotonep_fc_id[i]);
        }
        printf("\n");
    }

    printf("\n");
    marker = req->qmr_id;
    return;
}

static void
response_process(void *s)
{
    vr_response_common_process((vr_response *)s, &dump_pending);
    return;
}

static void
qosmap_fill_nl_callbacks()
{
    nl_cb.vr_fc_map_req_process = fc_map_req_process;
    nl_cb.vr_qos_map_req_process = qos_map_req_process;
    nl_cb.vr_response_process = response_process;
}

static int
vr_qos_map_op(void)
{
    int ret;
    unsigned int num_dscp, num_mpls_qos, num_dotonep;
    bool dump = false;

op_retry:
    num_dscp = num_mpls_qos = num_dotonep = 0;

    if (get_fc_set) {
        ret = vr_send_fc_map_get(cl, 0, qos_index);
    } else if (set_fc_set) {
        ret = vr_send_fc_map_add(cl, 0, (int16_t *)&qos_index, 1,
                &dscp, &mpls_qos, &dotonep, &queue);
    } else if (dump_fc_set) {
        dump = true;
        ret = vr_send_fc_map_dump(cl, 0, marker);
    } else if (get_qos_set) {
        ret = vr_send_qos_map_get(cl, 0, qos_index);
    } else if (set_qos_set) {
        if (dscp_set)
            num_dscp = 1;
        if (mpls_qos_set)
            num_mpls_qos = 1;
        if (dotonep_set)
            num_dotonep = 1;

        ret = vr_send_qos_map_add(cl, 0, qos_index,
                &dscp, num_dscp, &fc,
                &mpls_qos, num_mpls_qos, &fc,
                &dotonep, num_dotonep, &fc);
    } else if (dump_qos_set) {
        ret = vr_send_qos_map_dump(cl, 0, marker);
        dump = true;
    } else if (delete_qos_set) {
        ret = vr_send_qos_map_delete(cl, 0, qos_index);
    } else {
        ret = -EINVAL;
    }


    if (ret < 0)
        return ret;

    ret = vr_recvmsg(cl, dump);
    if (ret <= 0)
        return ret;

    if (dump_pending)
        goto op_retry;

    return ret;
}

static int
interface_queue_get(void)
{
    int ret;

    ret = vr_send_get_dcbx(cl, ifname);
    if (ret < 0) {
        printf("vRouter: GET of DCBX mode failed\n");
        return ret;
    }
    dcbx_mode = ret;

    if (dcbx_mode & DCB_CAP_DCBX_VER_CEE) {
        ret = vr_send_get_dcb_state(cl, ifname);
        if (ret < 0) {
            printf("vRouter: GET of DCB state failed\n");
            return ret;
        }

        dcb_enable = ret;

        memset(&priority_map, 0, sizeof(priority_map));
        ret = vr_send_get_priority_config(cl, ifname, &priority_map);
    } else if (dcbx_mode & DCB_CAP_DCBX_VER_IEEE) {
        ret = vr_send_get_ieee_ets(cl, ifname, &priority_map);
    } else {
        printf("vRouter: Unknown DCBX mode %x\n", dcbx_mode);
        return 0;
    }

    if (ret < 0) {
        printf("GET Priority Config failed on interface %s\n", ifname);
        return ret;
    }

    dump_priority();

    return 0;
}

static int
interface_queue_set(void)
{
    int ret, i;

    ret = vr_send_set_dcbx(cl, ifname, dcbx_mode | DCB_CAP_DCBX_HOST);
    if (ret < 0)
        return ret;

    if (dcbx_mode == DCB_CAP_DCBX_VER_CEE) {
        ret = vr_send_set_dcb_state(cl, ifname, 1);
        if (ret < 0)
            return ret;

        ret = vr_send_set_priority_config(cl, ifname, &priority_map);
        if (ret < 0)
            return ret;

        ret = vr_send_set_dcb_all(cl, ifname);
        if (ret < 0)
            return ret;
    } else if (dcbx_mode == DCB_CAP_DCBX_VER_IEEE) {
        for (i = 0; i < 8; i++)
            priority_map.tc_to_group[i] = i;

        ret = vr_send_set_ieee_ets(cl, ifname, &priority_map);
        if (ret < 0)
            return ret;
    }

    return 0;
}

static int
qos_map_op(void)
{
    int ret;

    if (set_queue_set) {
        ret = interface_queue_set();
    } else if (get_queue_set) {
        ret = interface_queue_get();
    } else {
        ret = vr_qos_map_op();
    }

    return ret;
}

enum opt_qos_index {
    DCBX_MODE_OPT_INDEX,
    DELETE_QOS_MAP_OPT_INDEX,
    DUMP_FC_OPT_INDEX,
    DUMP_QOS_MAP_OPT_INDEX,
    DOTONEP_OPT_INDEX,
    DSCP_OPT_INDEX,
    MPLS_QOS_OPT_INDEX,
    FC_OPT_INDEX,
    GET_FC_OPT_INDEX,
    GET_QOS_MAP_OPT_INDEX,
    GET_QUEUE_OPT_INDEX,
    PRIORITY_GROUP_OPT_INDEX,
    PRIORITY_GROUP_BW_OPT_INDEX,
    QUEUE_ID_OPT_INDEX,
    SET_FC_OPT_INDEX,
    SET_QOS_MAP_OPT_INDEX,
    SET_QUEUE_OPT_INDEX,
    STRICT_OPT_INDEX,
    TC_OPT_INDEX,
    HELP_OPT_INDEX,
    MAX_OPT_INDEX
};


static int
extract_priority_to_tc_map(char *up2tc)
{
    char *tok;
    uint8_t *prio_to_tc = priority_map.prio_to_tc;
    unsigned int length, offset = 0, i = 0;
    unsigned long tc;

    length = strlen(up2tc);
    do {
        tok = vr_extract_token(up2tc + offset, ',');
        if (tok) {
            errno = 0;
            tc = strtoul(tok, NULL, 0);
            if (errno || tc > 7) {
                printf("Invalid value in the priority to tc mapping\n");
                return EINVAL;
            }
            prio_to_tc[i] = tc;
        }

        offset += strlen(tok) + 1;
    } while (tok && (++i < NUM_PRIO) && (offset < length));

    return 0;
}

static int
extract_strictness_map(char *strictness)
{
    unsigned int i;

    if (strlen(strictness) > NUM_TC) {
        printf("Invalid value in strictness\n");
        return EINVAL;
    }

    for (i = 0; i < NUM_TC; i++) {
        if (strictness[i] != '0') {
            if (strictness[i] != '1') {
                printf("Invalid value in strictness\n");
                return EINVAL;
            }
            priority_map.tc_strictness |= (1 << i);
        }
    }

    return 0;
}


static int
extract_priority_group_bandwidth(char *pgbw_string)
{
    char *tok;
    uint8_t *priority_group_bw = priority_map.prio_group_bw;
    unsigned int length, offset = 0, i = 0;
    unsigned long bandwidth;

    length = strlen(pgbw_string);
    do {
        tok = vr_extract_token(pgbw_string + offset, ',');
        if (tok) {
            errno = 0;
            bandwidth = strtoul(tok, NULL, 0);
            if (errno || (bandwidth > 100)) {
                printf("Invalid value in the priority group bandwidth\n");
                return EINVAL;
            }
            priority_group_bw[i] = bandwidth;
        }

        offset += strlen(tok) + 1;
    } while (tok && (++i < NUM_PG) && (offset < length));

    return 0;
}

static int
extract_priority_groups(char *pg_string)
{
    char *tok;
    uint8_t *tc_to_group = priority_map.tc_to_group;
    unsigned int length, offset = 0, i = 0;
    unsigned long group;

    length = strlen(pg_string);
    do {
        tok = vr_extract_token(pg_string + offset, ',');
        if (tok) {
            errno = 0;
            group = strtoul(tok, NULL, 0);
            if (errno) {
                printf("Invalid value in the priority groups\n");
                return EINVAL;
            }
            tc_to_group[i] = group;
        }

        offset += strlen(tok) + 1;
    } while (tok && (++i < NUM_TC) && (offset < length));

    return 0;
}

static int
get_dcbx_mode(char *mode)
{
    unsigned int len, op_mode = -EINVAL;

    len = strlen(mode);
    if (!len || len < 3 || len > 4)
        return op_mode;

    if (!strncmp(mode, "cee", strlen("cee")))
        op_mode = DCB_CAP_DCBX_VER_CEE;
    else if (!strncmp(mode, "ieee", strlen("ieee")))
        op_mode = DCB_CAP_DCBX_VER_IEEE;

    return op_mode;
}

static struct option long_options[] = {
    [DCBX_MODE_OPT_INDEX]           = {"dcbx",          required_argument,  &dcbx_set,          1},
    [DELETE_QOS_MAP_OPT_INDEX]      = {"delete-qos",    required_argument,  &delete_qos_set,    1},
    [DUMP_FC_OPT_INDEX]             = {"dump-fc",       no_argument,        &dump_fc_set,       1},
    [DUMP_QOS_MAP_OPT_INDEX]        = {"dump-qos",      no_argument,        &dump_qos_set,      1},
    [DOTONEP_OPT_INDEX]             = {"dotonep",       required_argument,  &dotonep_set,       1},
    [DSCP_OPT_INDEX]                = {"dscp",          required_argument,  &dscp_set,          1},
    [MPLS_QOS_OPT_INDEX]            = {"mpls_qos",      required_argument,  &mpls_qos_set,      1},
    [FC_OPT_INDEX]                  = {"fc",            required_argument,  &fc_set,            1},
    [GET_FC_OPT_INDEX]              = {"get-fc",        required_argument,  &get_fc_set,        1},
    [GET_QOS_MAP_OPT_INDEX]         = {"get-qos",       required_argument,  &get_qos_set,       1},
    [GET_QUEUE_OPT_INDEX]           = {"get-queue",     required_argument,  &get_queue_set,     1},
    [PRIORITY_GROUP_OPT_INDEX]      = {"pg",            required_argument,  &pg_set,            1},
    [PRIORITY_GROUP_BW_OPT_INDEX]   = {"bw",            required_argument,  &pg_bw_set,         1},
    [QUEUE_ID_OPT_INDEX]            = {"queue",         required_argument,  &queue_set,         1},
    [SET_FC_OPT_INDEX]              = {"set-fc",        required_argument,  &set_fc_set,        1},
    [SET_QOS_MAP_OPT_INDEX]         = {"set-qos",       required_argument,  &set_qos_set,       1},
    [SET_QUEUE_OPT_INDEX]           = {"set-queue",     required_argument,  &set_queue_set,     1},
    [STRICT_OPT_INDEX]              = {"strict",        required_argument,  &strict_set,        1},
    [TC_OPT_INDEX]                  = {"tc",            required_argument,  &tc_set,            1},
    [HELP_OPT_INDEX]                = {"help",          no_argument,        &help_set,          1},
    [MAX_OPT_INDEX]                 = { NULL,           0,                  0,                  0}
};


static void
Usage(void)
{
    printf("qosmap --get-fc <fc-id>\n");
    printf("       --set-fc <fc-id> <--dscp | --mpls_qos | --dotonep | --queue> <value>\n");
    printf("       --get-qos <index>\n");
    printf("       --set-qos <index> <--dscp | --mpls_qos | --dotonep> <value> --fc <fc-id>\n");
    printf("       --set-queue <ifname> --dcbx <cee | ieee> --pg 0,1,2.. --bw 10,20,.. --strict 101..\n");
    printf("       --get-queue <ifname>\n");
    printf("       --dump-fc\n");
    printf("       --dump-qos\n");
    printf("       --delete-qos <index>\n");

    exit(EINVAL);

    return;
}

static void
build_default_priority_to_tc_map(void)
{
    unsigned int i;
    if (dcbx_mode == DCB_CAP_DCBX_VER_IEEE) {
        for (i = 0; i < NUM_TC; i++) {
            priority_map.prio_to_tc[i] = i;
        }
        default_tc = 1;
    } else if (dcbx_mode == DCB_CAP_DCBX_VER_CEE) {
        for (i = 0; i < NUM_TC; i++) {
            priority_map.prio_to_tc[i] = priority_map.tc_to_group[i];
        }
        default_tc = 1;
    } else {
        printf("Incorrect mode \n");
        Usage();
        return;
    }

    return;
}

static void
validate_options(void)
{
    bool strict_bw_specified = false;

    unsigned int i, aggregate_bw = 0;
    unsigned int set = dotonep_set + mpls_qos_set + dscp_set + queue_set;
    unsigned int op_set = get_fc_set + get_qos_set + set_fc_set +
        set_qos_set + dump_fc_set + dump_qos_set + delete_qos_set + get_queue_set;

    if (set_queue_set && tc_set != 1) {
        build_default_priority_to_tc_map();
    }

    unsigned int prio_opt_set = dcbx_set + set_queue_set + pg_set + pg_bw_set + strict_set + tc_set + default_tc;

    if ((prio_opt_set || get_queue_set) &&
            (get_platform() != LINUX_PLATFORM)) {
        printf("Queue options are valid only for kernel based vRouter\n");
        exit(EINVAL);
    }

    if (op_set) {
        if (op_set != 1 || prio_opt_set) {
            goto exit_options;
        }
    } else if (prio_opt_set) {
        if (dcbx_mode & DCB_CAP_DCBX_VER_IEEE) {
            if (pg_set) {
                printf("--pg option is not accepted for IEEE mode\n");
                goto exit_options;
            }

            if (prio_opt_set != 5)
                goto exit_options;
        } else {
            if (prio_opt_set != 6) {
                goto exit_options;
            }
        }
    } else {
        goto exit_options;
    }

    if (get_fc_set) {
        if (fc_set || set) {
            printf("Invalid arguments for --get-fc\n");
            goto exit_options;
        }
    } else if (get_qos_set) {
        if (fc_set || set) {
            printf("Invalid arguments to --get-qos\n");
            goto exit_options;
        }
    } else if (set_fc_set) {
        if (fc_set || (set != 4)) {
            printf("Invalid options to --set-fc\n");
            goto exit_options;
        }
    } else if (set_qos_set) {
        if (set != 1 || !fc_set) {
            printf("Invalid options to --set-qos\n");
            goto exit_options;
        }
    } else if (dump_fc_set || dump_qos_set || delete_qos_set) {
        if (set) {
            printf("Invalid options\n");
            goto exit_options;
        }
    } else if (prio_opt_set) {
        if (set_queue_set) {
            for (i = 0; i < NUM_PG; i++) {
                if ((priority_map.tc_strictness & (1 << i)) &&
                        (priority_map.prio_group_bw[i])) {
                    if (!strict_bw_specified) {
                        strict_bw_specified = true;
                        printf("NOTE: Bandwidth specification does not work ");
                        printf("with strict priority\n");
                    }
                    priority_map.prio_group_bw[i] = 0;
                }

                aggregate_bw += priority_map.prio_group_bw[i];
                if (aggregate_bw > 100) {
                    printf("Aggregate bandwidth is greater than 100\n");
                    goto exit_options;
                }
            }
        }

        dump_priority();
    } else if (get_queue_set) {
        if (set) {
            printf("Invalid options\n");
            goto exit_options;
        }
    }

    return;

exit_options:
    Usage();
    return;
}

static void
parse_long_opts(int opt_index, char *opt_arg)
{
    unsigned int i;

    errno = 0;

    switch (opt_index) {
    case DCBX_MODE_OPT_INDEX:
        dcbx_mode = get_dcbx_mode(opt_arg);
        if (dcbx_mode < 0) {
            Usage();
        }

        if (dcbx_mode == DCB_CAP_DCBX_VER_IEEE) {
            for (i = 0; i < NUM_TC; i++) {
                priority_map.tc_to_group[i] = i;
            }
        }

        break;

    case DOTONEP_OPT_INDEX:
        dotonep = strtoul(opt_arg, NULL, 0);
        break;

    case DSCP_OPT_INDEX:
        dscp = strtoul(opt_arg, NULL, 0);
        break;

    case DUMP_FC_OPT_INDEX:
    case DUMP_QOS_MAP_OPT_INDEX:
        break;

    case PRIORITY_GROUP_OPT_INDEX:
        if (extract_priority_groups(optarg)) {
            Usage();
        }
        break;

    case PRIORITY_GROUP_BW_OPT_INDEX:
        if (extract_priority_group_bandwidth(optarg)) {
            Usage();
        }
        break;

    case MPLS_QOS_OPT_INDEX:
        mpls_qos = strtoul(opt_arg, NULL, 0);
        break;

    case FC_OPT_INDEX:
        fc = strtoul(opt_arg, NULL, 0);
        break;

    case QUEUE_ID_OPT_INDEX:
        queue = strtoul(opt_arg, NULL, 0);
        break;

    case DELETE_QOS_MAP_OPT_INDEX:
    case GET_QOS_MAP_OPT_INDEX:
    case GET_FC_OPT_INDEX:
    case SET_FC_OPT_INDEX:
    case SET_QOS_MAP_OPT_INDEX:
        qos_index = strtoul(opt_arg, NULL, 0);
        break;

    case GET_QUEUE_OPT_INDEX:
    case SET_QUEUE_OPT_INDEX:
        if_index = if_nametoindex(opt_arg);
        if (!if_index) {
            printf("%s: No such interface exist in the system\n", opt_arg);
            exit(EINVAL);
        }

        strncpy(ifname, opt_arg, IFNAMSIZ - 1);
        ifname[IFNAMSIZ - 1] = '\0';

        break;

    case STRICT_OPT_INDEX:
        if (extract_strictness_map(optarg)) {
            Usage();
        }
        break;

    case TC_OPT_INDEX:
        if (extract_priority_to_tc_map(optarg)) {
            Usage();
        }
        break;

    case HELP_OPT_INDEX:
    default:
        Usage();
        break;
    }

    if (errno) {
        perror("parse_long_opts");
        Usage();
    }

    return;
}

int
main(int argc, char *argv[])
{
    char opt;
    int ret, option_index;
    unsigned int sock_proto;

    qosmap_fill_nl_callbacks();

    while ((opt = getopt_long(argc, argv, "", long_options,
                    &option_index)) >= 0) {
        switch (opt) {
        case 0:
            parse_long_opts(option_index, optarg);
            break;

        default:
            Usage();
        }
    }

    validate_options();

    if (set_queue_set || get_queue_set) {
        sock_proto = NETLINK_ROUTE;
    } else {
        sock_proto = VR_NETLINK_PROTO_DEFAULT;
    }

    cl = vr_get_nl_client(sock_proto);
    if (!cl)
        exit(1);

    ret = qos_map_op();
    if (ret) {
        return ret;
    }

    return 0;
}
