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
#include "ini_parser.h"
#include "vr_packet.h"

#define TABLE_FLAG_VALID        0x1

#define MEM_DEV                 "/dev/flow"
int mem_fd;

static int dvrf_set, mir_set, show_evicted_set, help_set, match_set;
static unsigned short dvrf;
static int list, flow_cmd, mirror = -1;
static unsigned long flow_index;
static int rate, stats;

/* match variables */
static unsigned int match_family, match_family_size;
static int32_t match_port1 = -1, match_port2 = -1;
static int32_t match_proto = -1, match_vrf = -1;
static char *match_ip1, *match_ip2;

/* to accommodate '*' */
bool match_ip1_set, match_ip2_set;

struct flow_table {
    struct vr_flow_entry *ft_entries;
    u_int64_t ft_entries_p;
    u_int64_t ft_span;
    u_int64_t ft_processed;
    u_int64_t ft_created;
    u_int64_t ft_added;
    unsigned int ft_num_entries;
    unsigned int ft_flags;
    unsigned int ft_cpus;
    unsigned int ft_hold_oflows;
    unsigned int ft_hold_stat_count;
    unsigned int ft_oflow_entries;
    u_int32_t ft_hold_stat[128];
    char flow_table_path[256];
} main_table;

struct nl_client *cl;
vr_flow_req flow_req;


struct vr_flow_entry *
flow_get(unsigned long flow_index)
{
    if (flow_index >= main_table.ft_num_entries)
        return NULL;

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
dump_legend(void)
{
    printf("Action:F=Forward, D=Drop ");
    printf("N=NAT(S=SNAT, D=DNAT, Ps=SPAT, Pd=DPAT, ");
    printf("L=Link Local Port)\n");

    printf(" Other:K(nh)=Key_Nexthop, S(nh)=RPF_Nexthop\n");
    printf(" Flags:E=Evicted, Ec=Evict Candidate, N=New Flow, M=Modified\n");
    printf("TCP(r=reverse):S=SYN, F=FIN, R=RST, C=HalfClose, E=Established, D=Dead\n");
    printf("\n");

    return;
}

static bool
match_dest(struct vr_flow_entry *fe, uint8_t *addr, int32_t port)
{
    if (!addr && (port < 0))
        return false;

    if (!memcmp(&fe->fe_key.flow_ip[VR_IP_ADDR_SIZE(fe->fe_type)],
                addr, match_family_size)) {
        if (port < 0)
            return true;
        if (ntohs(fe->fe_key.flow_dport) == port)
            return true;
    }

    return false;
}

static bool
match_source(struct vr_flow_entry *fe, uint8_t *addr, int32_t port)
{
    if (!addr && (port < 0))
        return false;

    if (!addr || !memcmp(fe->fe_key.flow_ip, addr, match_family_size)) {
        if (port < 0)
            return true;
        if (ntohs(fe->fe_key.flow_sport) == port)
            return true;
    }

    return false;
}

static char *
flow_proto_string(unsigned short proto)
{
    switch (proto) {
    case VR_IP_PROTO_TCP:
        return "TCP";
        break;

    case VR_IP_PROTO_UDP:
        return "UDP";
        break;

    case VR_IP_PROTO_ICMP:
        return "ICMP";
        break;

    case VR_IP_PROTO_SCTP:
        return "SCTP";
        break;

    case VR_IP_PROTO_ICMP6:
        return "ICMPv6";
        break;


    default:
        return "UNKNOWN";
    }

    return "UNKNOWN";
}

static void
dump_table(struct flow_table *ft)
{
    unsigned int i, j, k, fi, next_index, need_flag_print = 0, printed = 0;
    struct vr_flow_entry *fe, *ofe;
    char action, flag_string[sizeof(fe->fe_flags) * 8 + 32];
    unsigned int need_drop_reason = 0;
    const char *drop_reason = NULL;
    char in_src[INET6_ADDRSTRLEN], in_dest[INET6_ADDRSTRLEN];
    char addr[INET6_ADDRSTRLEN];
    bool smatch, dmatch;

    printf("Flow table(size %lu, entries %u)\n\n", ft->ft_span,
            ft->ft_num_entries);
    printf("Entries: Created %lu Added %lu Processed %lu Used Overflow entries %u\n",
            ft->ft_created, ft->ft_added, ft->ft_processed,
            ft->ft_oflow_entries);
    printf("(Created Flows/CPU: ");
    for (i = 0; i < ft->ft_hold_stat_count; i++) {
        printf("%u", ft->ft_hold_stat[i]);
        if (i != (ft->ft_hold_stat_count - 1))
            printf(" ");
    }
    printf(")(oflows %u)\n\n", ft->ft_hold_oflows);

    dump_legend();

    if (match_family || (match_proto > 0) || (match_vrf > 0)) {
        printf("Listing flows matching (");
        if (match_ip1_set) {
            if (match_ip1) {
                inet_ntop(match_family, match_ip1, addr, INET6_ADDRSTRLEN);
                printed += printf("[%s]", addr);
            } else {
                printed += printf("[*]");
            }

            if (match_port1 >= 0)
                printed += printf(":%u", match_port1);
            else
                printed += printf(":*");
        }

        if (match_ip2_set) {
            if (printed)
                printf(", ");

            if (match_ip2) {
                inet_ntop(match_family, match_ip2, addr, INET6_ADDRSTRLEN);
                printed += printf("[%s]", addr);
            } else {
                printed += printf("[*]");
            }

            if (match_port2 >= 0)
                printed += printf(":%u", match_port2);
            else
                printed += printf(":*");
        }

        if (match_proto >= 0) {
            if (printed)
                printf(", ");
            printed += printf("Protocol %s", flow_proto_string(match_proto));
        }

        if (match_vrf >= 0) {
            if (printed)
                printf(", ");
            printf("VRF %d", match_vrf);
        }

        printf(")");
        printed = 0;
        printf("\n\n");
    }

    printf("    Index            ");
    /* inter field gap */
    printf("%4c", ' ');
    /* 40 byte address field - middled header */
    printf("Source:Port/Destination:Port                  ");
    /* inter field gap */
    printf("%4c", ' ');
    printf("Proto(V)\n");
    printf("-----------------------------------------------------------------");
    printf("------------------\n");
    for (i = 0; i < ft->ft_num_entries; i++) {
        bzero(flag_string, sizeof(flag_string));
        need_flag_print = 0;
        need_drop_reason = 0;
        fe = (struct vr_flow_entry *)((char *)ft->ft_entries + (i * sizeof(*fe)));
        if (fe->fe_flags & VR_FLOW_FLAG_ACTIVE) {

            if ((fe->fe_flags & VR_FLOW_FLAG_EVICTED) &&
                    !show_evicted_set) {
                continue;
            }


            if (match_vrf >= 0) {
                if (fe->fe_vrf != match_vrf)
                    continue;
            }

            if (match_proto >= 0) {
                if (fe->fe_key.flow_proto != match_proto)
                    continue;
            }

            if (match_family) {
                if (match_family != VR_FLOW_FAMILY(fe->fe_type)) {
                    continue;
                }

                if (match_ip1_set) {
                    smatch = match_source(fe, match_ip1, match_port1);
                    if (!smatch) {
                        dmatch = match_dest(fe, match_ip1, match_port1);
                    }
                } else {
                    smatch = dmatch = false;
                }

                if (match_ip2_set) {
                    if (smatch) {
                        dmatch = match_dest(fe, match_ip2, match_port2);
                        if (!dmatch)
                            continue;
                    } else if (dmatch) {
                        smatch = match_source(fe, match_ip2, match_port2);
                        if (!smatch)
                            continue;
                    } else {
                        smatch = match_source(fe, match_ip2, match_port2);
                        if (!smatch) {
                            dmatch = match_dest(fe, match_ip2, match_port2);
                        }

                    }
                }

                if (!smatch && !dmatch)
                    continue;
            }


            if ((fe->fe_type == VP_TYPE_IP) || (fe->fe_type == VP_TYPE_IP6)) {
                inet_ntop(VR_FLOW_FAMILY(fe->fe_type), fe->fe_key.flow_ip,
                            in_src, sizeof(in_src));
                inet_ntop(VR_FLOW_FAMILY(fe->fe_type),
                      &fe->fe_key.flow_ip[VR_IP_ADDR_SIZE(fe->fe_type)],
                      in_dest, sizeof(in_dest));
            }

            printf("%9d", i);
            if (fe->fe_rflow >= 0)
                printf("<=>%-9d", fe->fe_rflow);
            else
                printf("%12c", ' ');

            printf("%4c", ' ');
            if (fe->fe_type == VP_TYPE_IP) {
                printed = printf("%s:%-5d", in_src, ntohs(fe->fe_key.flow_sport));
                for (k = printed; k < 46; k++)
                    printf(" ");
                printf("%4c", ' ');
                printf("%3d (%d", fe->fe_key.flow_proto, fe->fe_vrf);
                if (fe->fe_flags & VR_FLOW_FLAG_VRFT)
                    printf("->%d", fe->fe_dvrf);
                printf(")\n");
                printf("%25c", ' ');
                printf("%s:%-5d", in_dest, ntohs(fe->fe_key.flow_dport));
            } else if (fe->fe_type == VP_TYPE_IP6) {
                printed = printf("%s:%-5d    ", in_src, ntohs(fe->fe_key.flow_sport));
                for (k = printed; k < 46; k++)
                    printf(" ");
                printf("%4c", ' ');
                printf("%3d (%d", fe->fe_key.flow_proto, fe->fe_vrf);
                if (fe->fe_flags & VR_FLOW_FLAG_VRFT)
                    printf("->%d", fe->fe_dvrf);
                printf(")\n");
                printf("%25c", ' ');
                printf("%s:%-5d    ", in_dest, ntohs(fe->fe_key.flow_dport));
            }

            printf("\n");

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

            printf("(");
            printf("Gen: %u, ", fe->fe_gen_id);
            if ((fe->fe_type == VP_TYPE_IP) || (fe->fe_type == VP_TYPE_IP6))
                printf("K(nh):%u, ", fe->fe_key.flow_nh_id);

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
            printf("Flags:");
            if (fe->fe_flags & VR_FLOW_FLAG_EVICTED)
                printf("E");
            if (fe->fe_flags & VR_FLOW_FLAG_EVICT_CANDIDATE)
                printf("Ec");
            if (fe->fe_flags & VR_FLOW_FLAG_NEW_FLOW)
                printf("N");
            if (fe->fe_flags & VR_FLOW_FLAG_MODIFIED)
                printf("M");

            printf(", ");
            if (fe->fe_key.flow4_proto == VR_IP_PROTO_TCP) {
                printf("TCP:");

                if (fe->fe_tcp_flags & VR_FLOW_TCP_SYN)
                    printf("S");
                if (fe->fe_tcp_flags & VR_FLOW_TCP_SYN_R)
                    printf("Sr");
                if (fe->fe_tcp_flags & VR_FLOW_TCP_ESTABLISHED)
                    printf("E");
                if (fe->fe_tcp_flags & VR_FLOW_TCP_ESTABLISHED_R)
                    printf("Er");

                if (fe->fe_tcp_flags & VR_FLOW_TCP_FIN)
                    printf("F");
                if (fe->fe_tcp_flags & VR_FLOW_TCP_FIN_R)
                    printf("Fr");
                if (fe->fe_tcp_flags & VR_FLOW_TCP_RST)
                    printf("R");
                if (fe->fe_tcp_flags & VR_FLOW_TCP_HALF_CLOSE)
                    printf("C");
                if (fe->fe_tcp_flags & VR_FLOW_TCP_DEAD)
                    printf("D");

                printf(", ");
            }

            if (fe->fe_ecmp_nh_index >= 0)
                printf("E:%d, ", fe->fe_ecmp_nh_index);

            printf("S(nh):%u, ", fe->fe_src_nh_index);
            printf(" Stats:%u/%u, ", fe->fe_stats.flow_packets,
                    fe->fe_stats.flow_bytes);
            if (fe->fe_flags & VR_FLOW_FLAG_MIRROR) {
                printf(" Mirror Index :");
                if (fe->fe_mirror_id < VR_MAX_MIRROR_INDICES)
                    printf(" %d", fe->fe_mirror_id);
                if (fe->fe_sec_mirror_id < VR_MAX_MIRROR_INDICES)
                    printf(", %d, ", fe->fe_sec_mirror_id);
            }
            printf(" SPort %d", fe->fe_udp_src_port);
            printf(")");
        }

        j = -1;
        next_index = fe->fe_hentry.hentry_next_index;
        while (next_index != VR_INVALID_HENTRY_INDEX) {
            ofe = (struct vr_flow_entry *)((char *)ft->ft_entries +
                        (next_index * sizeof(*fe)));
            if (j == -1) {
                if (!(fe->fe_flags & VR_FLOW_FLAG_ACTIVE))
                    printf("%6d", i);

                printf("\n     Oflow entries:\n\t");
                j = 0;
            }
            j += printf(" %d", ofe->fe_hentry.hentry_index);
            if (j > 65) {
                printf("\n     ");
                j = 0;
            }

            next_index = ofe->fe_hentry.hentry_next_index;
        }

        if ((fe->fe_flags & VR_FLOW_FLAG_ACTIVE) || (j != -1))
            printf("\n\n");
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
                if (fe->fe_flags & VR_FLOW_FLAG_EVICTED) {
                    continue;
                }
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

        /* On Ubuntu system() is declared with warn_unused_result
         * attribute, so we suppress the warning
         */
        if (system("clear") == -1) {
            printf("Error: system() failed\n");
        }

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
                if (fe->fe_flags & VR_FLOW_FLAG_EVICTED) {
                    continue;
                }
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
    unsigned int i;
    struct flow_table *ft = &main_table;
    const char *flow_path;

    if (req->fr_ftable_dev < 0)
        exit(ENODEV);

    const char *platform = read_string(DEFAULT_SECTION, PLATFORM_KEY);
    if (platform && ((strcmp(platform, PLATFORM_DPDK) == 0) ||
                (strcmp(platform, PLATFORM_NIC) == 0))) {
        flow_path = req->fr_file_path;
    } else {
        flow_path = MEM_DEV;
        ret = mknod(MEM_DEV, S_IFCHR | O_RDWR,
                makedev(req->fr_ftable_dev, req->fr_rid));
        if (ret && errno != EEXIST) {
            perror(MEM_DEV);
            exit(errno);
        }
    }

    mem_fd = open(flow_path, O_RDONLY | O_SYNC);
    if (mem_fd <= 0) {
        perror(MEM_DEV);
        exit(errno);
    }

    ft->ft_entries = (struct vr_flow_entry *)mmap(NULL, req->fr_ftable_size,
            PROT_READ, MAP_SHARED, mem_fd, 0);
    /* the file descriptor is no longer needed */
    close(mem_fd);
    if (ft->ft_entries == MAP_FAILED) {
        printf("flow table: %s\n", strerror(errno));
        exit(errno);
    }

    ft->ft_span = req->fr_ftable_size;
    ft->ft_num_entries = ft->ft_span / sizeof(struct vr_flow_entry);
    ft->ft_processed = req->fr_processed;
    ft->ft_created = req->fr_created;
    ft->ft_hold_oflows = req->fr_hold_oflows;
    ft->ft_added = req->fr_added;
    ft->ft_cpus = req->fr_cpus;
    ft->ft_oflow_entries = req->fr_oflow_entries;

    if (req->fr_hold_stat && req->fr_hold_stat_size) {
        ft->ft_hold_stat_count = req->fr_hold_stat_size;
        for (i = 0; i < req->fr_hold_stat_size; i++) {
            if (i ==
                    (sizeof(ft->ft_hold_stat) / sizeof(ft->ft_hold_stat[0]))) {
                ft->ft_hold_stat_count = i;
                break;
            }

            ft->ft_hold_stat[i] = req->fr_hold_stat[i];
        }
    } else {
        ft->ft_hold_stat_count = 0;
        memset(ft->ft_hold_stat, 0, sizeof(ft->ft_hold_stat));
    }

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

    if ((ret = nl_recvmsg(cl)) > 0) {
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

    parse_ini_file();
    ret = nl_socket(cl, get_domain(), get_type(), get_protocol());
    if (ret <= 0)
        return ret;

    ret = nl_connect(cl, get_ip(), get_port());
    if (ret < 0)
        return ret;

    ret = vrouter_get_family_id(cl);
    if (ret <= 0)
        return ret;

    return ret;
}

void
flow_validate(unsigned long flow_index, char action)
{
    struct vr_flow_entry *fe;

    memset(&flow_req, 0, sizeof(flow_req));

    fe = flow_get(flow_index);
    if (!fe)
        return;

    if ((fe->fe_type != VP_TYPE_IP) && (fe->fe_type != VP_TYPE_IP6))
        return;

    flow_req.fr_op = FLOW_OP_FLOW_SET;
    flow_req.fr_index = flow_index;
    flow_req.fr_family = VR_FLOW_FAMILY(fe->fe_type);
    flow_req.fr_flags = VR_FLOW_FLAG_ACTIVE;
    flow_req.fr_flow_ip = malloc(2 * VR_IP_ADDR_SIZE(fe->fe_type));
    if (!flow_req.fr_flow_ip) {
        printf("Unable to allocate %u bytes for storing address\n",
                2 * VR_IP_ADDR_SIZE(fe->fe_type));
        return;
    }

    memcpy(flow_req.fr_flow_ip, fe->fe_key.flow_ip,
              2 * VR_IP_ADDR_SIZE(fe->fe_type));
    flow_req.fr_flow_ip_size = 2 * VR_IP_ADDR_SIZE(fe->fe_type);
    flow_req.fr_flow_proto = fe->fe_key.flow_proto;
    flow_req.fr_flow_sport = fe->fe_key.flow_sport;
    flow_req.fr_flow_dport = fe->fe_key.flow_dport;
    flow_req.fr_flow_nh_id = fe->fe_key.flow_nh_id;

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
        goto exit_validate;
    }

    if (mirror >= 0) {
        flow_req.fr_mir_id = mirror;
        flow_req.fr_flags |= VR_FLOW_FLAG_MIRROR;
    } else
        flow_req.fr_flags &= ~VR_FLOW_FLAG_MIRROR;


    make_flow_req(&flow_req);

exit_validate:
    if (flow_req.fr_flow_ip) {
        free(flow_req.fr_flow_ip);
        flow_req.fr_flow_ip = NULL;
        flow_req.fr_flow_ip_size = 0;
    }

    return;
}

static void
Usage(void)
{
    printf("Usage:flow [-f flow_index]\n");
    printf("           [-d flow_index]\n");
    printf("           [-i flow_index]\n");
    printf("           [--mirror=mirror table index]\n");
    printf("           [--match \"match_string\"\n");
    printf("           [-l]\n");
    printf("           [--show-evicted]\n");
    printf("           [-r]\n");
    printf("           [-s]\n");
    printf("\n");

    printf("-f <flow_index> Set forward action for flow at flow_index <flow_index>\n");
    printf("-d <flow_index> Set drop action for flow at flow_index <flow_index>\n");
    printf("-i <flow_index> Invalidate flow at flow_index <flow_index>\n");
    printf("--mirror        Mirror index to mirror to\n");
    printf("--match         Match criteria separated by a '&'; IP:PORT separated by a ','\n");
    printf("                e.g.: --match 1.1.1.1:20\n");
    printf("                      --match \"1.1.1.1:20,2.2.2.2:22\"\n");
    printf("                      --match \"[fe80::225:90ff:fec3:afa]:22\"\n");
    printf("                      --match \"10.204.217.10:56910 & vrf 0 & proto tcp\"\n");
    printf("                      --match \"10.204.217.10:56910,169.254.0.3:22 & vrf 0 & proto tcp\"\n");
    printf("                              proto {tcp, udp, icmp, icmp6, sctp}\n");
    printf("-l              List flows\n");
    printf("--show-evicted  Show evicted flows too\n");
    printf("-r              Start dumping flow setup rate\n");
    printf("-s              Start dumping flow stats\n");
    printf("--help          Print this help\n");

    exit(-EINVAL);
}

enum opt_flow_index {
    DVRF_OPT_INDEX,
    MIRROR_OPT_INDEX,
    SHOW_EVICTED_OPT_INDEX,
    MATCH_OPT_INDEX,
    HELP_OPT_INDEX,
    MAX_OPT_INDEX
};

static struct option long_options[] = {
    [DVRF_OPT_INDEX]            = {"dvrf",          required_argument, &dvrf_set,           1},
    [MIRROR_OPT_INDEX]          = {"mirror",        required_argument, &mir_set,            1},
    [SHOW_EVICTED_OPT_INDEX]    = {"show-evicted",  no_argument,       &show_evicted_set,   1},
    [MATCH_OPT_INDEX]           = {"match",         required_argument, &match_set,          1},
    [HELP_OPT_INDEX]            = {"help",          no_argument,       &help_set,           1},
    [MAX_OPT_INDEX]             = { NULL,           0,                 0,                   0}
};

static void
validate_options(void)
{
    if (!flow_index && !list && !rate && !stats && !match_set)
        Usage();

    if (show_evicted_set && !list)
        Usage();

    return;
}

static void
flow_remove_trailing_space(char *addr)
{
    unsigned int len = strlen(addr);

    len -= 1;
    while ((*(addr + len) == ' ') && --len);
    *(addr + len + 1) = '\0';

    return;
}

static bool
valid_ipv6_address(const char *addr)
{
    unsigned int i = 0, j = 0, sep_count = 0;

    /* a '*' is treated as a valid address */
    if (!strncmp(addr, "*", 1) && (strlen(addr) == 1))
        return true;

    while (*(addr + i)) {
        if (isalnum(*(addr + i))) {
            j++;
        } else if (*(addr + i) == ':') {
            j = 0;
            sep_count++;
        } else {
            printf("match: \"%s\" is not a valid ipv6 address format\n", addr);
            return false;
        }

        if ((j > 4) || (sep_count > 7)) {
            printf("match: \"%s\" is not a valid ipv6 address format\n", addr);
            return false;
        }

        i++;
    }

    return true;
}

static bool
valid_ipv4_address(const char *addr)
{
    unsigned int i = 0, j = 0, sep_count = 0;

    /* a '*' is treated as a valid address */
    if (!strncmp(addr, "*", 1) && (strlen(addr) == 1))
        return true;

    /* every character should be either a digit or a '.' */
    while (*(addr + i)) {
        if (isdigit(*(addr + i))) {
            j++;
        } else if (i && (*(addr + i) == '.')) {
            j = 0;
            ++sep_count;
        } else {
            printf("match: \"%s\" is not a valid ipv4 address format\n", addr);
            return false;
        }

        if ((j > 3) || (sep_count > 3)) {
            printf("match: \"%s\" is not a valid ipv4 address format\n", addr);
            return false;
        }

        i++;
    }

    if (sep_count != 3) {
        printf("match: \"%s\" is not a valid ipv4 address format\n", addr);
        return false;
    }

    return true;
}

static int
flow_set_family(unsigned int family, char *addr, const char *port)
{
    uint8_t ip[VR_IP6_ADDRESS_LEN];
    uint8_t *mem = NULL, mem_size;

    if (match_ip1_set && match_ip2_set && (addr || port)) {
        printf("match: Why do you specify \"[%s]:%s\" when both ends of "
                "the flow are already specified\n", addr, port ? port : NULL);
        return -EINVAL;
    }

    flow_remove_trailing_space(addr);

    switch (family) {
    case AF_INET:
        mem_size = VR_IP_ADDRESS_LEN;
        if (!valid_ipv4_address(addr))
            return -EINVAL;
        break;

    case AF_INET6:
        mem_size = VR_IP6_ADDRESS_LEN;
        if (!valid_ipv6_address(addr))
            return -EINVAL;
        break;

    default:
        printf("match: Internal logic failure. Family is not one of inet/inet6\n");
        return -EINVAL;
    }

    if (match_family && (match_family != family)) {
        printf("match: You are trying to match v4 and v6 flow together\n");
        printf("match: It does not make sense to me at this point of time\n");

        return -EINVAL;
    }

    if (!match_family) {
        match_family = family;
        match_family_size = mem_size;
    }

    if (strlen(addr) != strlen("*")) {
        inet_pton(family, addr, ip);
        mem = malloc(mem_size);
        if (!mem) {
            printf("match: Memory Allocation failure. Try again\n");
            return -ENOMEM;
        }
        memcpy(mem, ip, mem_size);
    }

    if (!match_ip1_set) {
        match_ip1 = mem;
        if (port) {
            if (strncmp(port, "*", 1))
                match_port1 = strtoul(port, NULL, 0);
        }
        match_ip1_set = true;
    } else if (!match_ip2_set) {
        match_ip2 = mem;
        if (port) {
            if (strncmp(port, "*", 1))
                match_port2 = strtoul(port, NULL, 0);
        }
        match_ip2_set = true;
    }

    return 0;
}

/*
 * Separate out the individual (ip, port) combination
 *
 * For ipv4, the flow will be specified as
 * a.a.a.a:p OR a.a.a.a
 *
 * For ipv6, the corresponding format will be
 * [a:a::a:a]:p OR a:a::a:a
 */
static int
flow_set_tuple(char *ip_port)
{
    unsigned int len = strlen(ip_port);
    unsigned int address_len;

    char *f_colon_sep, *b_colon_sep, *bracket_sep;

    /* for ipv6 addresses starting with '[' */
    bracket_sep = strchr(ip_port, '[');
    if (bracket_sep) {
        /* ...look for closing bracket */
        bracket_sep = strrchr(ip_port, ']');
        if (!bracket_sep) {
            printf("match: No closing ']'\n");
            return -EINVAL;
        }


        address_len = bracket_sep - ip_port + 1;
        /* post ']', we should have a ':' and a port number */
        if (((len - address_len) < 2) ||
                (ip_port[address_len] != ':')) {
            printf("match: match string should be in "
                    "[aa:aa::aa:aa]:p format\n");
            return -EINVAL;
        }

        /* replace the ']' with NULL */
        ip_port[address_len - 1] = '\0';
        /* the address string is already terminated with NULL */
        if (flow_set_family(AF_INET6, ip_port + 1, ip_port + address_len + 1))
            return -EINVAL;

    } else {
        f_colon_sep = strchr(ip_port, ':');
        /*
         * if it is an ipv6 address, we expect to see at least two different
         * ':'
         */
        if (f_colon_sep) {
            b_colon_sep = strrchr(ip_port, ':');
            if (b_colon_sep != f_colon_sep) {
                /* ...hence ipv6 */
                flow_set_family(AF_INET6, ip_port, NULL);
            } else {
                /*
                 * if they are the same, then it has to be v4 and the
                 * ':' is a port separator
                 */
                ip_port[f_colon_sep - ip_port] = '\0';
                if (flow_set_family(AF_INET, ip_port,
                        ip_port + (f_colon_sep - ip_port) + 1))
                    return -EINVAL;
            }
        } else {
            /* ...and if there are no ':', then the address is an ipv4 one */
            if (flow_set_family(AF_INET, ip_port, NULL))
                return -EINVAL;
        }
    }

    return 0;
}

static char *
flow_extract_token(char *string, char token_separator)
{
    int ret;
    unsigned int length;

    char *sep;

    /* skip over leading white spaces */
    while ((*string == ' ') && string++);

    /* if there is nothing left after the spaces, return */
    if (!strlen(string)) {
        return NULL;
    }

    /* start searching for the token */
    sep = strchr(string, token_separator);
    if (sep) {
        length = sep - string;
        /* terminate the token with NULL */
        string[sep - string] = '\0';
    }

    return string;
}

static int
flow_set_ip(char *match_string)
{
    int ret;
    unsigned int length = strlen(match_string), token_length;

    char *token, *string = match_string;

    do {
        token = flow_extract_token(match_string, ',');
        if (token) {
            token_length = strlen(token) + 1;
            /* ...and use it to set the match tuple */
            if (ret = flow_set_tuple(token))
                return ret;
        } else {
            token = flow_extract_token(match_string, '&');
            if (token) {
                token_length = strlen(token) + 1;
                if (ret = flow_set_tuple(token))
                    return ret;
            }
        }

        match_string = token + token_length;
    } while (!ret && token && ((match_string - string) < length));

    return 0;
}

static int
flow_set_vrf(char *string)
{
    if (!strlen(string))
        return -EINVAL;

    errno = 0;
    match_vrf = strtoul(string, NULL, 0);
    if (errno)
        return -errno;

    return 0;
}

static int
flow_set_proto(char *string)
{
    if (!strlen(string))
        return -EINVAL;

    if (!strncmp(string, "tcp", strlen("tcp"))) {
        match_proto = VR_IP_PROTO_TCP;
    } else if (!strncmp(string, "udp", strlen("udp"))) {
        match_proto = VR_IP_PROTO_UDP;
    } else if (!strncmp(string, "icmp6", strlen("icmp6"))) {
        match_proto =  VR_IP_PROTO_ICMP6;
    } else if (!strncmp(string, "icmp", strlen("icmp"))) {
        match_proto = VR_IP_PROTO_ICMP;
    } else if (!strncmp(string, "sctp", strlen("sctp"))) {
        match_proto = VR_IP_PROTO_SCTP;
    } else {
        printf("Unsupported protocol \"%s\"\n", string);
        return -EINVAL;
    }

    return 0;
}

static int
flow_set_match(char *match_string)
{
    int ret = 0;
    unsigned int length = strlen(match_string), token_length;
    char *token, *string = match_string;

    do {
        token = flow_extract_token(match_string, '&');
        if (token) {
            token_length = strlen(token) + 1;
            if (!strncmp(token, "proto", strlen("proto"))) {
                ret = flow_set_proto(token + strlen("proto") + 1);
            } else if (!strncmp(token, "vrf", strlen("vrf"))) {
                ret = flow_set_vrf(token + strlen("vrf") + 1);
                ret = flow_set_vrf(token + strlen("vrf") + 1);
            } else {
                ret = flow_set_ip(token);
            }
        }
        match_string = token + token_length;
    } while (!ret && token && ((match_string - string) < length));

    return ret;
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

    case MATCH_OPT_INDEX:
        if (flow_set_match(opt_arg))
            exit(-EINVAL);
        list = 1;
        break;

    case SHOW_EVICTED_OPT_INDEX:
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

    if (list) {
        flow_list();
    } else if (rate) {
        flow_rate();
    } else if (stats) {
        flow_stats();
    } else {
        if (flow_index >= main_table.ft_num_entries) {
            printf("Flow index %lu is greater than available indices (%u)\n",
                    flow_index, main_table.ft_num_entries - 1);
            return -1;
        }

        flow_validate(flow_index, flow_cmd);
    }

    return 0;
}
