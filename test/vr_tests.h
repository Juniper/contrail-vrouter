#ifndef VROUTER_UTILS_TESTS_H
#define VROUTER_UTILS_TESTS_H 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <stdbool.h>
#include <getopt.h>

#include <asm/types.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>

#include <net/if.h>
#include <netinet/ether.h>
#include "vr_interface.h"

#include "vr_types.h"
#include "vr_message.h"
#include "vr_nexthop.h"
#include "vr_genetlink.h"
#include "nl_util.h"

#define MAX_STR 100
#define MAX_STR_SIZE MAX_STR

#define TOTAL_TESTCASES 10
#define COMPOSITE_NEXTHOP_LEN 2

#ifndef VR_MAX_VRFS
#define VR_MAX_VRFS 4096
#endif

#ifndef VR_MAX_LABELS
#define VR_MAX_LABELS 5120
#endif

#ifndef VR_MAX_MIRROR_INDICES
#define VR_MAX_MIRROR_INDICES 255 
#endif

enum a{
INTERFACE,
NEXTHOP,
ROUTE,
VXLAN,
MPLS,
MIRROR,
FLOW,
TESTCASE_MAX
};

extern struct nl_client *cl;
extern int resp_code;
extern int total_pass[TOTAL_TESTCASES];
extern int  total_fail[TOTAL_TESTCASES];
extern int offset;
extern int attr_len;
extern void vr_route_testcases();
extern int soft_reset();
extern void cleanup();
#endif
