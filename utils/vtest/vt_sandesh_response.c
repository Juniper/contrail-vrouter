#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <libxml/xmlmemory.h>

#include <vtest.h>
#include <vr_types.h>
#include <vt_gen_lib.h>

#include <nl_util.h>

struct expect_vrouter expect_msg;
struct return_vrouter return_msg;

static void
interface_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_interface_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_interface_req)));
}

static void
nexthop_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_nexthop_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_nexthop_req)));
}

static void
route_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_route_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
        (memcpy(buf, s, sizeof(vr_route_req)));

}

static void
response_process(void *s) {
    vr_response *buf = (vr_response *)s;

    return_msg.returned_ptr_num++;
    return_msg.return_val[return_msg.returned_ptr_num] = buf->resp_code;
}

static void
vrf_stats_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_vrf_stats_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
        (memcpy(buf, s, sizeof(vr_vrf_stats_req)));
}

static void
vt_vrouter_ops_process(void *s) {
    void *buf = calloc(1, sizeof(vrouter_ops));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
        (memcpy(buf, s, sizeof(vrouter_ops)));
}

static void
vrf_assign_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_vrf_assign_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_vrf_assign_req)));

}

static void
flow_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_flow_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_flow_req)));

}

static void
flow_response_process(void *s) {
    void *buf = calloc(1, sizeof(vr_flow_response));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_flow_response)));

}

static void
vxlan_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_vxlan_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_vxlan_req)));

}

static void
drop_stats_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_drop_stats_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_drop_stats_req)));

}

static void
mpls_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_mpls_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_mpls_req)));
}

static void
mirror_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_mirror_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_mirror_req)));
}

static void
mem_stats_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_mem_stats_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_mem_stats_req)));
}

static void
hugepage_config_process(void *s) {
    void *buf = calloc(1, sizeof(vr_hugepage_config));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_hugepage_config)));
}

void
vt_fill_nl_callbacks()
{
    nl_cb.vr_interface_req_process = interface_req_process;
    nl_cb.vr_nexthop_req_process = nexthop_req_process;
    nl_cb.vr_route_req_process = route_req_process;
    nl_cb.vr_response_process = response_process;
    nl_cb.vr_vrf_stats_req_process = vrf_stats_req_process;
    nl_cb.vrouter_ops_process = vt_vrouter_ops_process;
    nl_cb.vr_vrf_assign_req_process = vrf_assign_req_process;
    nl_cb.vr_flow_req_process = flow_req_process;
    nl_cb.vr_flow_response_process = flow_response_process;
    nl_cb.vr_vxlan_req_process = vxlan_req_process;
    nl_cb.vr_drop_stats_req_process = drop_stats_req_process;
    nl_cb.vr_mpls_req_process = mpls_req_process;
    nl_cb.vr_mirror_req_process = mirror_req_process;
    nl_cb.vr_mem_stats_req_process = mem_stats_req_process;
    nl_cb.vr_hugepage_config_process = hugepage_config_process;
}
