
Vtest - vRouter unit test framework.


KNOWN ISSUES:
------------
Multicast is not supported.
Agent test cases are not supported.
Generator makes mem leak, when generator parses string, then allocs mem...
Does not support burst/batch virtio communication (only one free desc).
 -> Framentation/refragramentation will not work.

General:

No formal XML Schema.
vif name must be same as vif id.
Needs rewrite generator 
For some messages you need fill some "interesting" data.
      for example:
      when you want send a nh message (tunnel type)
      you must fill xml element value to integer = (inet_pton("1.1.1.1"))

      In generator/parser are lot of bugs like this  ^. 



INTRODUCTION
-------------
Vtest parses a XML file.  Based on parsed data sends/receive sandesh messages
and/or emulates VMs communication via VIRTUAL (virtio compatible) interfaces. 


The framework is divided into three parts
1) sandesh message communication
2) data communication
3) generator



BUILDING INTEGRATION
--------------------

For vtest purpose you don't have to load any kernel modules like rte or igb_uio to run vRouter.
If you have compiled vRouter you can test it.


!!! IMPORTANT !!!

After every test vRouter must be hard restarted. vRouter has lot of internal
values, which are incremented per packet and they MAY change values of packets. 

!!!!!!!!!!!!!!!!!!



XML DEFINITION
--------------

The non formal XML definition is following:
<test>
    <test_name> Name of test </test_name>

<!-- Sandesh message -->
    <message>
        <sandesh_type_req>
            <sandesh_attr_values>..</sandesh_attr_values> 
            ...
        </sandesh_type_req>    

    <return>0</return>
    <expected>
        <sandesh_type_expected>
            <sandesh_attr_values>..</sandesh_attr_values>
            ...
        </sandesh_type_expected>
    </expected>

    </message>
    ...

<!-- Data communication -->
    <packet>
        <pcap_input_file>...</pcap_input_file>
        <pcap_expected_file>...</pcap_expected_file>
        <tx_interface>
            <vif_index>...</vif_index>
        </tx_interface>
        <rx_interface>
            <vif_index>2</vif_index>
            ...
        </rx_interface>

    </packet>

</test>


Where XML element test_name defines 'name of test'.


*Sandesh messages*

Element message defines, sandesh message.
Elements sandesh_type_req are defined as structures of sandesh message (more info: sandesh definition)
XML element return, defines value of return message from vRouter.

The expected element is using in cases when we wants some information from vRouter
e.g: type of interface.

*Data communication*

The data communication is based on virtio protocol -> only virtual interfaces (vifs)
are supported.

Element pcap_input_file specifies a path to the source pcap file, a element pcap_expected_file
specifies a path to the expected pcap.

tx_interface defines source interface, rx_interface defines destination interfaces.
vtest support multiple interfaces for rx_interface, however multicast has not yet implemented.
element vif_index defines interface's id.


Folder example/ contains many examples, which are more detailed.


Currently, there is not XML schema.


 
1) SANDESH MESSAGES
-------------------

The vtest sends and receives messages from vRouter, 

The structure for messages are defined in vrouter/sandesh/vr.defs
 
If you want to create a new message for example vxlan_req, you must 

create following XML (I am skipping probably mandatory parts like nexthop(nh) messages).

<test>
    <test_name>VXLAN - HELLO WORLD </test_name>
...
    <message>
         <vr_vxlan_req> // structure name in vr.sandesh
            <h_op>ADD<h_op>
            <vxlanr_rid> ... </vxlanr_rid>
            <vxlanr_vnid>...</vxlanr_vnid>
            <vxlanr_nhid>...</vxlanr_nhid> //strucutre's attributes 

        <vr_vxlan_req>        
    <return>expected return value from vRouter -> message is correct</return>
    </message>
...
</test>



2) DATA COMMUNICATION
---------------------

The data communication uses the library (libjnprvnet), the source codes of library
are in folder ./vhost. You can create library make lib. If you want to play
only with data communication, in folder ./vhost/example is file example.c, which
describes library API.



!!! IMPORTANT !!!
vRouter should run only with one dedicated core, because data part does not 
support virtio's batch/burst mode (performance problem).

otherwise vRouter MAY drop packets.


vtest must be linked with the library...

!!!!!!!!!!!!!!!

*HOW TO CREATE A PCAP FILE*

Personaly, I recommend the python utility scapy (http://www.secdev.org/projects/scapy/doc/).
Exists version for python3 too, but I have not tested it.

Example:

#create one packet

packet = Ether(src="00:00:00:00:01", dst="00:00:00:00:02")/IP(src="1.1.1.1", dst="2.2.2.2")/UDP(sport=1, dport=42)/Raw("Kde bolo tam bolo")

#with the structure
packet.show()
###[ Ethernet ]###
  dst= 00:00:00:00:02
  src= 00:00:00:00:01
  type= 0x800
###[ IP ]###
     version= 4
     ihl= None
     tos= 0x0
     len= None
     id= 1
     flags= 
     frag= 0
     ttl= 64
     proto= udp
     chksum= None
     src= 1.1.1.1
     dst= 2.2.2.2
     \options\
###[ UDP ]###
        sport= 1
        dport= 42
        len= None
        chksum= None
###[ Raw ]###
           load= 'Kde bolo tam bolo'


#we are saving packet to the file example.pcap
wrpcap("example.pcap", packet)



3) GENERATOR:
-------------

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


