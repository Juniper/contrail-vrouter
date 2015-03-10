/*
 * dropstats.c - drop statistics
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#if defined(__linux__)
#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>

#include <net/if.h>
#include <netinet/ether.h>
#elif defined(__FreeBSD__)
#include <net/if.h>
#include <net/ethernet.h>
#endif

#include "vr_types.h"
#include "vr_message.h"
#include "vr_nexthop.h"
#include "vr_genetlink.h"
#include "nl_util.h"
#include "vr_os.h"
#include "vr_stats.h"

static struct nl_client *cl;
static int resp_code;
static vr_drop_stats_req stats_req;
static vr_drop_stats_register register_req;
static int help_set;
static int proto_set,src_ip_set,dst_ip_set,src_port_set;
static int dst_port_set,filtered_set,vrf_set,get_filter_set;
static int register_set,unregister_set;
static char *proto,*src_ip,*dst_ip,*src_port,*dst_port,*vrf;
static char str[INET_ADDRSTRLEN];
static unsigned int stats_op;
void
vr_drop_stats_req_process(void *s_req)
{
    vr_drop_stats_req *stats = (vr_drop_stats_req *)s_req;
    if(!stats){
        printf("Unable to retrive stats\n");
    }

    printf("GARP                          %" PRIu64 "\n",
            stats->vds_garp_from_vm);
    printf("ARP no where to go            %" PRIu64 "\n",
            stats->vds_arp_no_where_to_go);
    printf("Invalid ARPs                  %" PRIu64 "\n",
            stats->vds_invalid_arp);
    printf("\n");

    printf("Invalid IF                    %" PRIu64 "\n",
            stats->vds_invalid_if);
    printf("Trap No IF                    %" PRIu64 "\n",
            stats->vds_trap_no_if);
    printf("IF TX Discard                 %" PRIu64 "\n",
            stats->vds_interface_tx_discard);
    printf("IF Drop                       %" PRIu64 "\n",
            stats->vds_interface_drop);
    printf("IF RX Discard                 %" PRIu64 "\n",
            stats->vds_interface_rx_discard);
    printf("\n");

    printf("Flow Unusable                 %" PRIu64 "\n",
            stats->vds_flow_unusable);
    printf("Flow No Memory                %" PRIu64 "\n",
            stats->vds_flow_no_memory);
    printf("Flow Table Full               %" PRIu64 "\n",
            stats->vds_flow_table_full);
    printf("Flow NAT no rflow             %" PRIu64 "\n",
            stats->vds_flow_nat_no_rflow);
    printf("Flow Action Drop              %" PRIu64 "\n",
            stats->vds_flow_action_drop);
    printf("Flow Action Invalid           %" PRIu64 "\n",
            stats->vds_flow_action_invalid);
    printf("Flow Invalid Protocol         %" PRIu64 "\n",
            stats->vds_flow_invalid_protocol);
    printf("Flow Queue Limit Exceeded     %" PRIu64 "\n",
            stats->vds_flow_queue_limit_exceeded);
    printf("\n");

    printf("Discards                      %" PRIu64 "\n",
            stats->vds_discard);
    printf("TTL Exceeded                  %" PRIu64 "\n",
            stats->vds_ttl_exceeded);
    printf("Mcast Clone Fail              %" PRIu64 "\n",
            stats->vds_mcast_clone_fail);
    printf("Cloned Original               %" PRIu64 "\n",
            stats->vds_cloned_original);
    printf("\n");

    printf("Invalid NH                    %" PRIu64 "\n",
            stats->vds_invalid_nh);
    printf("Invalid Label                 %" PRIu64 "\n",
            stats->vds_invalid_label);
    printf("Invalid Protocol              %" PRIu64 "\n",
            stats->vds_invalid_protocol);
    printf("Rewrite Fail                  %" PRIu64 "\n",
            stats->vds_rewrite_fail);
    printf("Invalid Mcast Source          %" PRIu64 "\n",
            stats->vds_invalid_mcast_source);
    printf("\n");

    printf("Push Fails                    %" PRIu64 "\n",
            stats->vds_push);
    printf("Pull Fails                    %" PRIu64 "\n",
            stats->vds_pull);
    printf("Duplicated                    %" PRIu64 "\n",
            stats->vds_duplicated);
    printf("Head Alloc Fails              %" PRIu64 "\n",
            stats->vds_head_alloc_fail);
    printf("Head Space Reserve Fails      %" PRIu64 "\n",
            stats->vds_head_space_reserve_fail);
    printf("PCOW fails                    %" PRIu64 "\n",
            stats->vds_pcow_fail);
    printf("Invalid Packets               %" PRIu64 "\n",
            stats->vds_invalid_packet);
    printf("\n");

    printf("Misc                          %" PRIu64 "\n",
            stats->vds_misc);
    printf("Nowhere to go                 %" PRIu64 "\n",
            stats->vds_nowhere_to_go);
    printf("Checksum errors               %" PRIu64 "\n",
            stats->vds_cksum_err);
    printf("No Fmd                        %" PRIu64 "\n",
            stats->vds_no_fmd);
    printf("Invalid VNID                  %" PRIu64 "\n",
            stats->vds_invalid_vnid);
    printf("Fragment errors               %" PRIu64 "\n",
            stats->vds_frag_err);
    printf("Invalid Source                %" PRIu64 "\n",
            stats->vds_invalid_source);
    printf("Jumbo Mcast Pkt with DF Bit   %" PRIu64 "\n",
            stats->vds_mcast_df_bit);
    printf("ARP No Route                  %" PRIu64 "\n",
            stats->vds_arp_no_route);
    printf("ARP Reply No Route            %" PRIu64 "\n",
            stats->vds_arp_reply_no_route);
    printf("No L2 Route                   %" PRIu64 "\n",
            stats->vds_l2_no_route);
    printf("\n");
    return;
}

static void print_all_options() {
    printf("proto %s\n",proto);
    printf("src ip %s\n",src_ip);
    printf("dst-ip %s\n",dst_ip);
    printf("dst port %s\n",dst_port);
    printf("src port %s\n",src_port);
}
void
vr_response_process(void *s)
{
    vr_response *stats_resp;

    stats_resp = (vr_response *)s;
    resp_code = stats_resp->resp_code;

    if (stats_resp->resp_code < 0) {
        if(stats_resp->resp_code == -NO_FILTER_REGISTERED)
            printf("NO filter is registered for counting drop stats\n");
        else
            printf("Error %s in kernel operation\n", strerror(stats_resp->resp_code));
        exit(-1);
    }
    return;
}


static vr_drop_stats_req *
vr_build_drop_stats_request(void)
{
    stats_req.h_op = SANDESH_OP_GET;
    stats_req.vds_rid = 0;
    if(filtered_set)
        stats_req.vds_is_filtered=1;
    else
        stats_req.vds_is_filtered=0;
    return &stats_req;
}
static unsigned int pton(char *ipst){
    struct in_addr ip;
    if(ipst)
        if(inet_aton(ipst,&ip))
            return ip.s_addr;
        else
            return -1;

    else
        return -1;
}
static int ntop(int ip)
{
    struct sockaddr_in sa;
    sa.sin_addr.s_addr = ip;
    if(inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN))
        return 1;
    else
        return 0;
}
static vr_drop_stats_register *
vr_build_drop_stats_register(void)
{
    int ret=0;
    memset(&register_req, 0, sizeof(vr_drop_stats_register));
    if(register_set) {
        register_req.h_op = SANDESH_OP_ADD;
        if(src_ip && (register_req.source_ip=pton(src_ip)) <0)
            goto error;
        if(dst_ip && (register_req.destination_ip=pton(dst_ip)) <0)
            goto error;
        if(src_port && (register_req.source_port = atoi(src_port))<0)
            goto error;
        if(dst_port && (register_req.destination_port = atoi(dst_port))<0)
            goto error;
        if(proto && (register_req.protocol = atoi(proto))<0)
            goto error;
        if(vrf && (register_req.vrf = atoi(vrf)) <0)
            goto error;
    }
    else if(get_filter_set)
        register_req.h_op = SANDESH_OP_GET;
    else
        register_req.h_op = SANDESH_OP_DELETE;

    return &register_req;
    error:
    return NULL;
}

static int
vr_build_netlink_request(void *req, char *op)
{
    int ret, error = 0, attr_len;

    /* nlmsg header */
    ret = nl_build_nlh(cl, cl->cl_genl_family_id, NLM_F_REQUEST);
    if (ret)
        return ret;

    /* Generic nlmsg header */
    ret = nl_build_genlh(cl, SANDESH_REQUEST, 0);
    if (ret)
        return ret;

    attr_len = nl_get_attr_hdr_size();
    ret = sandesh_encode(req, op, vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error)
        return -1;

    /* Add sandesh attribute */
    nl_build_attr(cl, ret, NL_ATTR_VR_MESSAGE_PROTOCOL);
    nl_update_nlh(cl);
    return 0;
}

static int
vr_send_one_message(void)
{
    int ret;
    struct nl_response *resp;

    ret = nl_sendmsg(cl);
    if (ret <= 0)
        return 0;

    while ((ret = nl_recvmsg(cl)) > 0) {
        resp = nl_parse_reply(cl);
        if (resp->nl_op == SANDESH_REQUEST)
            sandesh_decode(resp->nl_data, resp->nl_len, vr_find_sandesh_info, &ret);
    }

    return resp_code;
}

static void
vr_drop_stats_op(void)
{
    vr_send_one_message();
    return;
}

static int 
vr_get_drop_stats(void)
{
    int ret;
    vr_drop_stats_req *req;

    req = vr_build_drop_stats_request();
    if (!req)
        return -errno;

    ret = vr_build_netlink_request(req,"vr_drop_stats_req");
    if (ret < 0)
        return ret;

    vr_drop_stats_op();

    return 0;
}
static int
vr_register_drop_stats(void) {
    int ret;
    vr_drop_stats_register *reg_req;
    reg_req = vr_build_drop_stats_register();
    if (!reg_req)
        return -errno;

    ret = vr_build_netlink_request(reg_req,"vr_drop_stats_register");
    if (ret < 0)
        return ret;

    vr_drop_stats_op();
    return 0;
}
enum opt_index {
    REGISTER,
    UNREGISTER,
    PROTOCOL_INDEX,
    SOURCE_IP_INDEX,
    DESTINATION_IP_INDEX,
    SOURCE_PORT_INDEX,
    DESTINATION_PORT_INDEX,
    VRF_INDEX,
    FILTERED_OPT_INDEX,
    GET_FILTER_OPT_INDEX,
    HELP_OPT_INDEX,
    MAX_OPT_INDEX,

};

static struct option long_options[] = {
        [REGISTER]          = {"register",no_argument, &register_set, 1},
        [UNREGISTER]        = {"unregister",no_argument, &unregister_set, 1},
        [PROTOCOL_INDEX]    = {"proto", optional_argument, &proto_set, 1 },
        [SOURCE_IP_INDEX]   = {"src_ip",    optional_argument, &src_ip_set, 1 },
        [DESTINATION_IP_INDEX]  = {"dst_ip",    optional_argument, &dst_ip_set,1 },
        [SOURCE_PORT_INDEX] = {"src_port",  optional_argument, &src_port_set, 1 },
        [DESTINATION_PORT_INDEX]    = {"dst_port",  optional_argument, &dst_port_set,1 },
        [VRF_INDEX]         = {"vrf", optional_argument, &vrf_set,1},
        [FILTERED_OPT_INDEX] = {"filtered",no_argument,&filtered_set,1},
        [GET_FILTER_OPT_INDEX] = {"get_filter",no_argument,&get_filter_set,1},
        [HELP_OPT_INDEX]    =   {"help",    no_argument,        &help_set,      1},
        [MAX_OPT_INDEX]     =   {"NULL",    0,                  0,              0},
};

static void
Usage()
{
    printf("Usage: drop_stats [--help]\n");
    printf("Usage: drop_stats --register --proto=<proto> --src_ip=<ip>\n");
    printf("               --src_port=<src port> --dst_ip=<dst ip>\n");
    printf("                --dst_port=<dst port> --vrf=<vrf>\n");
    printf("\n");
    printf("Usage: drop_stats --unregister\n");
    printf("Usage: drop_stats --filtered\n");
    printf("Usage: drop_stats --get_filter\n");
    exit(-EINVAL);
}

static void
parse_long_opts(int opt_index, char *opt_arg)
{
    errno = 0;
    switch (opt_index) {
    case REGISTER:
        stats_op = SANDESH_OP_ADD;
        break;
    case UNREGISTER:
        stats_op = SANDESH_OP_DELETE;
        break;
    case PROTOCOL_INDEX:
        proto = opt_arg;
        break;
    case SOURCE_IP_INDEX:
        src_ip=opt_arg;
        break;
    case DESTINATION_IP_INDEX:
        dst_ip=opt_arg;
        break;
    case SOURCE_PORT_INDEX:
        src_port=opt_arg;
        break;
    case DESTINATION_PORT_INDEX:
        dst_port=opt_arg;
        break;
    case VRF_INDEX:
        vrf = opt_arg;
        break;
    case FILTERED_OPT_INDEX:
        stats_op = SANDESH_OP_GET;
        break;
    case GET_FILTER_OPT_INDEX:
        stats_op = SANDESH_OP_GET;
        break;
    default:
        break;
    }


    return;
}
static void
validate_options(void)
{
    int options;
    options = proto_set + src_ip_set+dst_ip_set+src_port_set+dst_ip_set+vrf_set;
    if(filtered_set || unregister_set || get_filter_set)
        if (options)
            Usage();
    if(register_set)
        if (!options)
            Usage();
    if (help_set)
        Usage();

    return;
}
void vr_drop_stats_register_process(void *response ) {
    vr_drop_stats_register *filter  = (vr_drop_stats_register *)response;
    if(filter){
        printf("Registered Filter \n");
        if(filter->source_ip){
            ntop(filter->source_ip);
            printf("Source IP: %s\n",str);
        }
        else
            printf("Source IP: *\n");
        if(filter->destination_ip){
            ntop(filter->destination_ip);
            printf("Destination IP: %s\n",str);
        }
        else
            printf("Destination IP: *\n");
        if(filter->source_port)
            printf("Source Port: %d\n",filter->source_port);
        else
            printf("source Port: *\n");
        if(filter->destination_port)
            printf("Destination Port: %d\n",filter->destination_port);
        else
            printf("Destination Port: *\n");
        if(filter->protocol)
            printf("Protocol: %d\n",filter->protocol);
        else
            printf("Protocol: *\n");

        if(filter->vrf)
            printf("VRF: %d\n",filter->vrf);
        else
            printf("VRF: *\n");
    }
    else
        printf("Unable to get filter \n");

}

int
main(int argc, char *argv[])
{
    char opt;
    int ret, option_index;

    while (((opt = getopt_long(argc, argv, "",
            long_options, &option_index)) >= 0)) {
        switch (opt) {
        case 0:
            parse_long_opts(option_index, optarg);
            break;

        default:
            Usage();
        }
    }
    validate_options();
    cl = nl_register_client();
    if (!cl) {
        exit(1);
    }

    ret = nl_socket(cl, NETLINK_GENERIC);
    if (ret <= 0) {
        exit(1);
    }

    if (vrouter_get_family_id(cl) <= 0) {
        return -1;
    }
    if(register_set||unregister_set || get_filter_set) {
        if(vr_register_drop_stats()<0)
            printf("Unable to complete the operation\n");
    }

    else
        vr_get_drop_stats();

    return 0;
}
