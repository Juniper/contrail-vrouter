#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <libxml/xmlmemory.h>

#include <vtest.h>
#include <vr_types.h>
#include <vt_gen_lib.h>


struct expect_vrouter expect_msg;
struct return_vrouter return_msg;

void
vr_interface_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_interface_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_interface_req)));
}

void
vr_nexthop_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_nexthop_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_nexthop_req)));
}

void
vr_route_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_route_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
        (memcpy(buf, s, sizeof(vr_route_req)));

}

void
vr_response_process(void *s) {
    vr_response *buf = (vr_response *)s;

    return_msg.returned_ptr_num++;
    return_msg.return_val[return_msg.returned_ptr_num] = buf->resp_code;
}

void
vr_vrf_stats_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_vrf_stats_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
        (memcpy(buf, s, sizeof(vr_vrf_stats_req)));
}

void
vrouter_ops_process(void *s) {
    void *buf = calloc(1, sizeof(vrouter_ops));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
        (memcpy(buf, s, sizeof(vrouter_ops)));
}

void
vr_vrf_assign_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_vrf_assign_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_vrf_assign_req)));

}

void
vr_flow_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_flow_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_flow_req)));

}

void
vr_flow_response_process(void *s) {
    void *buf = calloc(1, sizeof(vr_flow_response));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_flow_response)));

}

void
vr_vxlan_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_vxlan_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_vxlan_req)));

}

void
vr_drop_stats_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_drop_stats_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_drop_stats_req)));

}

void
vr_mpls_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_mpls_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_mpls_req)));
}

void
vr_mirror_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_mirror_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_mirror_req)));
}

void
vr_mem_stats_req_process(void *s) {
    void *buf = calloc(1, sizeof(vr_mem_stats_req));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_mem_stats_req)));
}

void
vr_hugepage_config_process(void *s) {
    void *buf = calloc(1, sizeof(vr_hugepage_config));
    if (!buf) {
        fprintf(stderr, "Cannot alloc memory \n");
        exit(ENOMEM);
    }

    expect_msg.expected_ptr_num++;
    expect_msg.mem_expected_msg[expect_msg.expected_ptr_num] =
    (memcpy(buf, s, sizeof(vr_hugepage_config)));
}
