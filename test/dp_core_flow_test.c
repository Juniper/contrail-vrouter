#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "vr_types.h"
#include "vr_os.h"
#include "vr_packet.h"
#include "vr_message.h"
#include "vr_interface.h"
#include "vr_nexthop.h"
#include "vrouter.h"

#include "host/vr_host.h"
#include "host/vr_host_packet.h"
#include "host/vr_host_interface.h"

#define NEXTHOP_1   12
#define VRF_1       3
#define INTF_1      5
#define OS_INTF_1   8

extern int vrouter_host_init(unsigned int);
extern unsigned int vr_num_cpus;

/*
 * Install some wrapped functions
 */
struct vr_nexthop *
__real___vrouter_get_nexthop(struct vrouter *router, unsigned int index);

struct vr_nexthop *
__wrap___vrouter_get_nexthop(struct vrouter *router, unsigned int index)
{
    struct vr_nexthop *(*fnc)(struct vrouter *, unsigned int);

    /* Use a specific function if a mock has been installed */
    fnc = (struct vr_nexthop *(*)(struct vrouter *, unsigned int))mock();
    if (fnc)
        return fnc(router, index);
    return __real___vrouter_get_nexthop(router, index);
}

int
__real_vr_message_response(unsigned int object_type, void *object, int ret);

int
__wrap_vr_message_response(unsigned int object_type, void *object, int ret)
{
    check_expected(object_type);
    check_expected(ret);

    return 0;
}

static int
_trap_vif_send(struct vr_interface *vif, struct vr_packet *pkt, void *params) {
    int (*fnc)(struct vr_interface *, struct vr_packet *, void *);

    fnc = (int (*)(struct vr_interface *, struct vr_packet *, void *))mock();
    if (fnc) {
        return fnc(vif, pkt, params);
    }

    return 0;
}

static void
_vr_lib_schedule_work(unsigned int cpu, void (*fn)(void *), void *arg)
{
    fn(arg);
}

static void
_lh_defer(struct vrouter *router, vr_defer_cb user_cb, void *data)
{
    user_cb(router, data);
}

static uint32_t
atoip(const char *ip)
{
    struct sockaddr_in sin;

    inet_aton(ip, &sin.sin_addr);
    return sin.sin_addr.s_addr;
}

static void
_fill_flow_req(vr_flow_req *flow_req, struct vr_flow *flow)
{
    bzero(flow_req, sizeof(vr_flow_req));

    flow_req->fr_flow_ip = vr_zalloc(2 * VR_IP_ADDRESS_LEN);
    assert_non_null(flow_req->fr_flow_ip);

    memcpy(flow_req->fr_flow_ip, flow->flow_ip, 2 * VR_IP_ADDRESS_LEN);
    flow_req->fr_flow_sport = flow->flow4_sport;
    flow_req->fr_flow_dport = flow->flow4_dport;
    flow_req->fr_flow_proto = flow->flow4_proto;
    flow_req->fr_flow_nh_id = flow->flow4_nh_id;
    flow_req->fr_family = flow->flow4_family;
}

static int
_register_fake_nexthop(vr_nexthop_req *req, unsigned int id,
        unsigned int vrf, unsigned int family, unsigned int type)
{
    bzero(req, sizeof(vr_nexthop_req));
    req->nhr_id = id;
    req->nhr_family = family;
    req->nhr_type = type;
    req->nhr_vrf = vrf;
    req->nhr_flags = NH_FLAG_VALID;
    return vr_nexthop_add(req);
}

static int
_register_fake_interface(vr_interface_req *req, unsigned int idx,
        unsigned int type, unsigned int vrf, unsigned int nh_id,
        unsigned int os_idx, unsigned int ip)
{
    struct vr_hinterface *hif;

    hif = vr_hinterface_create(os_idx, HIF_TYPE_UDP, type);
    assert_non_null(hif);

    bzero(req, sizeof(vr_interface_req));
    req->vifr_type = type;
    req->vifr_idx = idx;
    req->vifr_vrf = vrf;
    req->vifr_mtu = 1500;
    req->vifr_os_idx = os_idx;
    req->vifr_nh_id = nh_id;
    req->vifr_ip = ip;
    req->vifr_transport = VIF_TRANSPORT_VIRTUAL;
    return vr_interface_add(req, false);
}

static unsigned int
_hold_count(struct vrouter *router)
{
    unsigned int i, num_cpus, hcount = 0;
    struct vr_flow_table_info *infop = router->vr_flow_table_info;

    num_cpus = vr_num_cpus;
    for (i = 0; i < num_cpus; i++)
        hcount += infop->vfti_hold_count[i];

    return hcount;
}

void
_vr_inet_fill_flow(struct vr_flow *flow, unsigned short nh_id,
        uint32_t sip, uint32_t dip, uint8_t proto,
        uint16_t sport, uint16_t dport)
{
    uint32_t ips[2];

    ips[0] = sip;
    ips[1] = dip;

    vr_inet_fill_flow(flow, nh_id, (unsigned char *)ips, proto, sport, dport);
}

void
test_new_flow_from_agent(void **state)
{
    struct vr_packet *pkt;
    struct vr_flow flow;
    vr_flow_req flow_req;
    struct vr_forwarding_md fmd;
    vr_nexthop_req nh_req;
    vr_interface_req vif_req;
    struct vr_interface *vif;
    struct vrouter *router;
    flow_result_t result;
    int rc;

    router = vrouter_get(0);

    rc = _register_fake_nexthop(&nh_req, NEXTHOP_1, VRF_1, AF_INET, NH_RCV);
    assert_int_equal(0, rc);

    rc = _register_fake_interface(&vif_req, INTF_1, VIF_TYPE_VIRTUAL, VRF_1,
            NEXTHOP_1, OS_INTF_1, atoip("10.0.0.2"));
    assert_int_equal(0, rc);

    _vr_inet_fill_flow(&flow, NEXTHOP_1,
            atoip("10.0.0.1"), atoip("10.0.0.2"),
            VR_IP_PROTO_UDP, htons(22), htons(33));

    _fill_flow_req(&flow_req, &flow);
    flow_req.fr_rid = 0;
    flow_req.fr_op = FLOW_OP_FLOW_SET;
    flow_req.fr_index = -1;
    flow_req.fr_action = VR_FLOW_ACTION_HOLD;
    flow_req.fr_flags |= VR_FLOW_FLAG_ACTIVE;

    assert_int_equal(0, router->vr_flow_table_info->vfti_action_count);
    assert_int_equal(0, _hold_count(router));

    /* will execute the real function */
    will_return(__wrap___vrouter_get_nexthop, NULL);

    expect_value(__wrap_vr_message_response, object_type, VR_FLOW_OBJECT_ID);
    expect_value(__wrap_vr_message_response, ret, 0);

    vr_flow_req_process(&flow_req);
    assert_int_equal(0, router->vr_flow_table_info->vfti_action_count);
    assert_int_equal(1, _hold_count(router));
}

static
int _callback_flow_from_agent_trap_validate(struct vr_interface *vif,
        struct vr_packet *pkt, struct agent_send_params *params)
{
    struct vr_flow_trap_arg *ta;
    unsigned int vrf, reason;

    check_expected(vif);

    assert_int_equal(AGENT_TRAP_FLOW_MISS, params->trap_reason);
    assert_int_equal(VRF_1, params->trap_vrf);
}

void
test_callback_flow_from_agent(void **state)
{
    struct vr_packet *pkt;
    struct vr_flow flow;
    vr_flow_req flow_req;
    struct vr_flow_entry *fe;
    struct vr_forwarding_md fmd;
    vr_nexthop_req nh_req;
    vr_interface_req vif_req;
    struct vr_interface *vif;
    struct vrouter *router;
    flow_result_t result;
    int rc, fe_index;

    router = vrouter_get(0);

    rc = _register_fake_nexthop(&nh_req, NEXTHOP_1, VRF_1, AF_INET, NH_RCV);
    assert_int_equal(0, rc);

    rc = _register_fake_interface(&vif_req, INTF_1, VIF_TYPE_VIRTUAL, VRF_1,
            NEXTHOP_1, OS_INTF_1, atoip("10.0.0.2"));
    assert_int_equal(0, rc);

    vif = __vrouter_get_interface(router, INTF_1);
    assert_non_null(vif);

    pkt = vr_palloc(300);
    pkt->vp_type = VP_TYPE_IP;
    pkt->vp_flags = 0;
    pkt->vp_if = vif;

    vr_init_forwarding_md(&fmd);
    fmd.fmd_vlan = 1;
    fmd.fmd_dvrf = VRF_1;

    _vr_inet_fill_flow(&flow, NEXTHOP_1,
            atoip("10.0.0.1"), atoip("10.0.0.2"),
            VR_IP_PROTO_UDP, htons(22), htons(33));

    /* will execute the real function */
    will_return_always(__wrap___vrouter_get_nexthop, NULL);

    will_return(_trap_vif_send,
            _callback_flow_from_agent_trap_validate);
    expect_any(_callback_flow_from_agent_trap_validate, vif);

    result = vr_flow_lookup(router, &flow, pkt, &fmd);
    assert_int_equal(FLOW_HELD, result);

    fe = vr_find_flow(router, &flow, VP_TYPE_IP, &fe_index);
    assert_non_null(fe);

    assert_int_equal(0, router->vr_flow_table_info->vfti_action_count);
    assert_int_equal(1, _hold_count(router));

    _fill_flow_req(&flow_req, &flow);
    flow_req.fr_rid = 0;
    flow_req.fr_op = FLOW_OP_FLOW_SET;
    flow_req.fr_index = fe_index;
    flow_req.fr_action = VR_FLOW_ACTION_FORWARD;
    flow_req.fr_flags |= VR_FLOW_FLAG_ACTIVE;

    expect_value(__wrap_vr_message_response, object_type, VR_FLOW_OBJECT_ID);
    expect_value(__wrap_vr_message_response, ret, 0);

    vr_flow_req_process(&flow_req);
    assert_int_equal(1, router->vr_flow_table_info->vfti_action_count);
    assert_int_equal(1, _hold_count(router));
}

static struct vr_nexthop *
_vrouter_get_nexthop_creating_new_flow(struct vrouter *router, unsigned int index)
{
    struct vr_flow flow;
    flow_result_t result;
    struct vr_packet *pkt;
    struct vr_forwarding_md fmd;
    struct vr_interface *vif;

    vr_init_forwarding_md(&fmd);
    fmd.fmd_vlan = 1;
    fmd.fmd_dvrf = VRF_1;

    vif = __vrouter_get_interface(router, INTF_1);
    assert_non_null(vif);

    pkt = vr_palloc(300);
    pkt->vp_type = VP_TYPE_IP;
    pkt->vp_flags = 0;
    pkt->vp_if = vif;

    _vr_inet_fill_flow(&flow, NEXTHOP_1,
            atoip("10.0.0.1"), atoip("10.0.0.2"),
            VR_IP_PROTO_UDP, htons(22), htons(33));

    /* will execute the real function */
    will_return(_trap_vif_send, NULL);

    result = vr_flow_lookup(router, &flow, pkt, &fmd);
    assert_int_equal(FLOW_HELD, result);

    return __real___vrouter_get_nexthop(router, index);
}

void
test_new_flow_concurrency(void **state)
{
    struct vr_flow flow;
    vr_flow_req flow_req;
    vr_nexthop_req nh_req;
    vr_interface_req vif_req;
    struct vr_interface *vif;
    struct vrouter *router;
    int rc;

    router = vrouter_get(0);

    rc = _register_fake_nexthop(&nh_req, NEXTHOP_1, VRF_1, AF_INET, NH_RCV);
    assert_int_equal(0, rc);

    rc = _register_fake_interface(&vif_req, INTF_1, VIF_TYPE_VIRTUAL, VRF_1,
            NEXTHOP_1, OS_INTF_1, atoip("10.0.0.2"));
    assert_int_equal(0, rc);

    _vr_inet_fill_flow(&flow, NEXTHOP_1,
            atoip("10.0.0.1"), atoip("10.0.0.2"),
            VR_IP_PROTO_UDP, htons(22), htons(33));

    _fill_flow_req(&flow_req, &flow);
    flow_req.fr_rid = 0;
    flow_req.fr_op = FLOW_OP_FLOW_SET;
    flow_req.fr_index = -1;
    flow_req.fr_action = VR_FLOW_ACTION_FORWARD;
    flow_req.fr_flags |= VR_FLOW_FLAG_ACTIVE;

    /*
     * install the mock version of the __vrouter_get_nexthop that will
     * create a new flow during the agent request
     */
    will_return(__wrap___vrouter_get_nexthop,
            _vrouter_get_nexthop_creating_new_flow);

    expect_value(__wrap_vr_message_response, object_type, VR_FLOW_OBJECT_ID);
    expect_value(__wrap_vr_message_response, ret, -ENOSPC);

    vr_flow_req_process(&flow_req);
}

static void
*_zalloc(unsigned int size)
{
    return calloc(1, size);
}

static void
setup_flow(void **state)
{
    struct vrouter *router;
    struct vr_interface *agent_vif;
    int rc;

    router = vrouter_get(0);

    vr_sandesh_init();
    vr_host_io_init();

    rc = vrouter_host_init(VR_MPROTO_SANDESH);
    assert_int_equal(0, rc);

    vrouter_host->hos_get_defer_data = (void *(*)(unsigned int)) malloc;
    vrouter_host->hos_malloc = (void *(*)(unsigned int)) malloc;
    vrouter_host->hos_zalloc = _zalloc;
    vrouter_host->hos_free = free;
    vrouter_host->hos_schedule_work = _vr_lib_schedule_work;
    vrouter_host->hos_defer = _lh_defer;

    rc = vr_flow_init(router);
    assert_int_equal(0, rc);

    rc = vr_interface_init(router);
    assert_int_equal(0, rc);

    rc = vr_nexthop_init(router);
    assert_int_equal(0, rc);

    if (!router->vr_agent_if) {
         agent_vif = (struct vr_interface *) malloc(sizeof(struct vr_interface));
         assert_non_null(agent_vif);

         agent_vif->vif_send = _trap_vif_send;
         router->vr_agent_if = agent_vif;
    }
}

static void
teardown_flow(void **state)
{
    struct vrouter *router;

    router = vrouter_get(0);

    vr_nexthop_exit(router, 1);
    vr_interface_exit(router, 1);
    vr_host_interface_exit();
    vr_sandesh_exit();

    vrouter_host_exit();
}

int
main(void)
{
    int ret;

    /* test suite */
    const UnitTest tests[] = {
        unit_test_setup_teardown(test_new_flow_from_agent,
                setup_flow, teardown_flow),
        unit_test_setup_teardown(test_callback_flow_from_agent,
                setup_flow, teardown_flow),
        unit_test_setup_teardown(test_new_flow_concurrency,
                setup_flow, teardown_flow),
    };

    /* let's run the test suite */
    ret = run_tests(tests);

    return ret;
}
