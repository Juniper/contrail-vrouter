The xml file specification
-------------------------

<?xml version="1.0"?>
<test>
    <test_name>Interface test</test_name>
    <message>
        <vif>
            <m_op>Add</m_op>
            <vif_type>Virtual</vif_type>
            <vif_index>4</vif_index>
            <vif_vrf>0</vif_vrf>
            <vif_mac>00:01:02:03:04:05</vif_mac>
            <vif_mtu>1514</vif_mtu>
        </vif>
        <message_return>0</message_return>
    </message>

    <test_result>
        <message>
            <vif>
                <m_op>Get</m_op>
                <vif_index>4</vif_index>
            </vif>
        </message>
        <message_return>0</message_return>
        <message_expect>
            <vif>
                <vif_type>Virtual</vif_type>
                <vif_index>4</vif_index>
                <vif_vrf>0</vif_vrf>
                <vif_mac>00:01:02:03:04:05</vif_mac>
                <vif_mtu>1514</vif_mtu>
            </vif>
        </message_expect>
    </test_result>

</test>

The generated code from sandesh file processing
-----------------------------------------------

There is a sandesh compiler that parses the sandesh file and autogenerates
code to read values from specification file and assign it to corresponding
variables of the sandesh structure. It takes care of all known data types
of sandesh message (including list<type> and string). As of now, the compiler
generates 'vt_gen_sandesh.c' (that contains the above described functionality)
, 'vt_gen_message_modules.c' (that contains the list of nodes under the message
module of vtest), 'vt_gen_message_modules.h' (a header file that contains all
the required declarations) and 'vt_gen_expect.c' that sanitizes the received
message with expected values from the specification file.

The generator is still evolving. More functionality will be added to generator
on need basis.


Snap of code generated in 'vt_gen_sandesh.c'
-------------------------------------------

....

void *
vr_nexthop_req_node(xmlNodePtr node, struct vtest *test)
{
    unsigned int list_size;
    vr_nexthop_req *req;

    req = calloc(sizeof(*req), 1);
    if (!req)
        return NULL;

    node = node->xmlChildrenNode;
    while (node) {
        if (!node->content || !strlen(node->content)) {
            return NULL;
        }

        if (!strncmp(node->name, "h_op", strlen(node->content))) {
            req->h_op = vt_gen_op(node->content);
        } else if (!strncmp(node->name, "nhr_type", strlen(node->content))) {
            req->nhr_type = strtoul(node->content, NULL, 0);
        } else if (!strncmp(node->name, "nhr_family", strlen(node->content))) {

....

        } else if (!strncmp(node->name, "nhr_label_list", strlen(node->content))) {
            req->nhr_label_list = vt_gen_list(node->content, GEN_TYPE_U32, &list_size);
            req->nhr_label_list_size = list_size;
        }
        node = node->next;
    }

    return (void *)req;
}

Snap of code generated in 'vt_gen_message_modules.c'
----------------------------------------------------

/*
 * Auto generated file
 */
#include <string.h>

#include <stdbool.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <vr_types.h>
#include <vt_gen_lib.h>
#include <vtest.h>

#include <vt_gen_message_modules.h>

struct vt_message_module vt_message_modules[] = {
    {  
        .vmm_name        =        "vr_nexthop_req",
        .vmm_node        =        vr_nexthop_req_node,
        .vmm_expect        =        vr_nexthop_req_expect,
        .vmm_size        =        sizeof(vr_nexthop_req),
    },
    {  
        .vmm_name        =        "vr_interface_req",
        .vmm_node        =        vr_interface_req_node,

....
....

    {  
        .vmm_name        =        "expect",
        .vmm_node        =        vt_expect_node,
        .vmm_size        =        0,
    },
};

unsigned int vt_message_modules_num =
        sizeof(vt_message_modules) / sizeof(vt_message_modules[0]);


Snap of code generated in 'vt_gen_message_modules.h'
---------------------------------------------------

/*
 * Auto generated file
 */
#ifndef __VT_GEN_MESSAGE_MODULES_H__
#define __VT_GEN_MESSAGE_MODULES_H__

#include <string.h>

#include <stdbool.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <vr_types.h>
#include <vt_gen_lib.h>
#include <vtest.h>

struct vt_message_module {
    char *vmm_name;
    void *(*vmm_node)(xmlNodePtr, struct vtest *);
    bool (*vmm_expect)(xmlNodePtr, struct vtest *, void *);
    unsigned int vmm_size;
};

extern void *vr_nexthop_req_node(xmlNodePtr, struct vtest *);
extern bool vr_nexthop_req_expect(xmlNodePtr, struct vtest *, void *);

....
....

extern void *vt_return_node(xmlNodePtr, struct vtest *);
extern void *vt_expect_node(xmlNodePtr, struct vtest *);

#endif

Snap of code generated in 'vt_gen_sandesh_expect.c'
--------------------------------------------------

/*
 * Auto generated file
 */
#include <string.h>

#include <stdbool.h>

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>

#include <vr_types.h>
#include <vt_gen_lib.h>
#include <vtest.h>

bool
vr_nexthop_req_expect(xmlNodePtr node, struct vtest *test, void *buf)
{   
    bool result = true;
    unsigned int list_size;
    vr_nexthop_req *req = (vr_nexthop_req *)buf;

    node = node->xmlChildrenNode;
    while (node) {
        if (!node->content || !strlen(node->content)) {
            return NULL;
        }

....
....

        } else if (!strncmp(node->name, "nhr_label_list", strlen(node->content))) {
            result = vt_gen_list_compare(req->nhr_label_list,
                    req->nhr_label_list_size, node->content, GEN_TYPE_U32);
        }

        if (!result)
            return result;

        node = node->next;
    }

    return result;
}


