/*
 * vr_llocal.c -- Link Local Port Management
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vrouter.h>
#include <vr_packet.h>
#include <vr_message.h>
#include <vr_sandesh.h>


static int
vr_link_local_port_make_req(vr_link_local_ports_req *resp, unsigned
        short port, unsigned short proto)
{
    resp->vllp_rid = 0;
    resp->vllp_port = htons(port);
    resp->vllp_marker = resp->vllp_port;
    resp->vllp_proto = htons(proto);
    return 0;
}
bool
vr_valid_link_local_port(struct vrouter *router, int family,
                         int proto, int port)
{
    unsigned char data;
    unsigned int tmp;

    if (!router->vr_link_local_ports)
        return false;

    if ((family != AF_INET) ||
        ((proto != VR_IP_PROTO_TCP) && (proto != VR_IP_PROTO_UDP)))
        return false;

    if ((port < VR_DYNAMIC_PORT_START) || (port > VR_DYNAMIC_PORT_END))
        return false;

    tmp = port - VR_DYNAMIC_PORT_START;
    if (proto == VR_IP_PROTO_UDP)
        tmp += (router->vr_link_local_ports_size * 8 / 2);

    data = router->vr_link_local_ports[(tmp / 8)];
    if (data & (1 << (tmp % 8)))
        return true;

    return false;
}

void
vr_clear_link_local_port(struct vrouter *router, int family,
                       int proto, int port)
{
    unsigned char *data;
    unsigned int tmp;

    if (!router->vr_link_local_ports)
        return;

    if ((family != AF_INET) ||
        ((proto != VR_IP_PROTO_TCP) && (proto != VR_IP_PROTO_UDP)))
        return;

    if ((port < VR_DYNAMIC_PORT_START) || (port > VR_DYNAMIC_PORT_END))
        return;

    tmp = port - VR_DYNAMIC_PORT_START;
    if (proto == VR_IP_PROTO_UDP)
        tmp += (router->vr_link_local_ports_size * 8 / 2);

    data = &router->vr_link_local_ports[(tmp / 8)];
    *data &= (~(1 << (tmp % 8)));

    return;
}

void
vr_set_link_local_port(struct vrouter *router, int family,
                       int proto, int port)
{
    unsigned char *data;
    unsigned int tmp;

    if (!router->vr_link_local_ports)
        return;

    if ((family != AF_INET) ||
        ((proto != VR_IP_PROTO_TCP) && (proto != VR_IP_PROTO_UDP)))
        return;

    if ((port < VR_DYNAMIC_PORT_START) || (port > VR_DYNAMIC_PORT_END))
        return;

    tmp = port - VR_DYNAMIC_PORT_START;
    if (proto == VR_IP_PROTO_UDP)
        tmp += (router->vr_link_local_ports_size * 8 / 2);

    data = &router->vr_link_local_ports[tmp / 8];
    *data |= (1 << (tmp % 8));

    return;
}

void
vr_link_local_ports_reset(struct vrouter *router)
{
    if (router->vr_link_local_ports) {
        memset(router->vr_link_local_ports,
               0, router->vr_link_local_ports_size);
    }

    return;
}

int
vr_link_local_ports_dump(vr_link_local_ports_req *r)
{
    unsigned char *ports;
    int bit, size, i, marker_byte, marker_bit, ret = 0;
    vr_link_local_ports_req resp;
    struct vr_message_dumper *dumper = NULL;
    struct vrouter *router = vrouter_get(r->vllp_rid);

   
    if (!router && (ret = -ENODEV))
        goto generate_response;

    if ((ntohs(r->vllp_proto) != VR_IP_PROTO_TCP) &&
            (ntohs(r->vllp_proto) != VR_IP_PROTO_UDP)) {
        ret = -EINVAL;
        goto generate_response;
    }

    dumper = vr_message_dump_init(r);
    if (!dumper && (ret = -ENOMEM))
        goto generate_response;

    size = router->vr_link_local_ports_size / 2;
    ports = router->vr_link_local_ports;
    if (ntohs(r->vllp_proto) == VR_IP_PROTO_UDP)
        ports += size;

    marker_byte = ntohs(r->vllp_marker) / 8;
    marker_bit = ntohs(r->vllp_marker) % 8;

    for (i = marker_byte; i < size; i++) {
        for (bit = 0; bit < 8; bit++) {
            if ((marker_byte != -1) && (bit <= marker_bit))
                continue;
            if (ports[i] & (1 << bit)) {
                vr_link_local_port_make_req(&resp, ((i * 8) + bit),
                        ntohs(r->vllp_proto));
                ret = vr_message_dump_object(dumper,
                        VR_LINK_LOCAL_OBJECT_ID, &resp);
                if (ret <= 0)
                    break;
            }
        }
        marker_byte = -1;
    }

generate_response:
    vr_message_dump_exit(dumper, ret);
    return 0;
}

/*
 * sandesh handler for vr_llocal_req
 */
void
vr_link_local_ports_req_process(void *s_req)
{

    int ret;
    vr_link_local_ports_req *req = (vr_link_local_ports_req *)s_req;

    switch (req->h_op) {

    case SANDESH_OP_DUMP:
        ret = vr_link_local_ports_dump(req);
        break;

    default:
        ret = -EOPNOTSUPP;
        vr_send_response(ret);
        break;
    }
}


void
vr_link_local_ports_exit(struct vrouter *router)
{
    if (router->vr_link_local_ports) {
        vr_free(router->vr_link_local_ports);
        router->vr_link_local_ports = NULL;
        router->vr_link_local_ports_size = 0;
    }

    return;
}

int
vr_link_local_ports_init(struct vrouter *router)
{
    unsigned int port_range, bytes;

    if (router->vr_link_local_ports)
        return 0;

    /*  Udp and TCP inclusive of low and high limits*/
    port_range = 2 * ((VR_DYNAMIC_PORT_END - VR_DYNAMIC_PORT_START) + 1);
    /* Make it 16 bit boundary */
    bytes = (port_range + 15) & ~15;
    /* Bits to Bytes */
    bytes /= 8;

    router->vr_link_local_ports = vr_zalloc(bytes);
    if (!router->vr_link_local_ports)
        return -1;
    router->vr_link_local_ports_size = bytes;

    return 0;
}

