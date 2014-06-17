#include "vr_tests.h"

int 
add_interface(int print)
{
    vr_interface_req vr_req;
    int ret=0,error=0;
    char *str=(char *) malloc(MAX_STR);

    if(!str) {
        printf("Memmory allocation has failed\n");
        exit(1);
    }

    //create a tap interface and attach to vif 

    setup_nl();
    sleep(1);
    memset(&vr_req,0,sizeof(vr_req));
    vr_req.h_op=SANDESH_OP_ADD;
    vr_req.vifr_type=VIF_TYPE_VIRTUAL;
    vr_req.vifr_flags=VIF_FLAG_L2_ENABLED;
    vr_req.vifr_idx= VR_MAX_INTERFACES-2 ;
    vr_req.vifr_name="TAPTEST";
    vr_req.vifr_os_idx=if_nametoindex("taptest");
    vr_req.vifr_mac_size=6;
    vr_req.vifr_mac="\x00\x12\x13\x14\x15\x16";

    ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);

    memset(str,0,MAX_STR);
    strncpy(str,"All feilds of vr_inreface_req are proper",MAX_STR-1);
    if(print)
        test_print(str,0,0);
}
int  
rcv_nexthop_testcases() 
{
    vr_nexthop_req nh_req;
    int ret=0,error=0;
    char *str=(char *) malloc(MAX_STR);

    if(!str) {
        printf("Memmory allocation has failed\n");
        exit(1);
    }

    printf("------------NEIGHBOUR add with type RCV test cases----------\n");

    //All praramaters are proper
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_encap_size = 0;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_RCV;

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"All feilds of vr_nexthop_req are proper",MAX_STR-1);
    test_print(str,0,0);


    //delete  with proper nhr_id
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_DELETE;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"delete an operation with proper nhr_id field in nexthop_req ",MAX_STR-1);
    test_print(str,0,0);

    //delete  nh with next hop id which is not there 
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_DELETE;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"delete nexthop which is not there test case   ",MAX_STR-1);
    test_print(str,-EINVAL,offsetof(vr_nexthop_req,nhr_id));

    //nhr_id has wrong value	
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_encap_size = 0;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES;
    nh_req.nhr_type=NH_RCV;

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"nhr_id feild has wrong value",MAX_STR-1);
    test_print(str,-EINVAL,offsetof(vr_nexthop_req,nhr_id));

    //nhr_type has worng value i.e. NH_MAX
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size = 0;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_MAX;

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"nhr_type feild has wrong value",MAX_STR-1);
    test_print(str,-EINVAL,offsetof(vr_nexthop_req,nhr_type));

    //nhr_encap_oif_id has wrong value i.e. VR_MAX_INTERFACES
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_encap_size = 0;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_RCV;

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"nhr_encap_oif_id",MAX_STR-1);
    test_print(str,-ENODEV,offsetof(vr_nexthop_req,nhr_encap_oif_id));
}
int
encap_nexthop_testcases() 
{
    vr_nexthop_req nh_req;
    int ret=0,error=0;
    char *str=(char *) malloc(MAX_STR);

    if(!str) {
        printf("Memmory allocation has failed\n");
        exit(1);
    }


    printf("-------------NEIGHBOUR ADD test case for ENCAP type----------\n");
    //All praramaters are proper
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_ENCAP;
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"All feilds of vr_nexthop_req are proper",MAX_STR-1);
    test_print(str,0,0);
    //delete opertion with proper nhr_id on encap type next hop
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_DELETE;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"delete an operation with proper nhr_id field in nexthop_req ",MAX_STR-1);
    test_print(str,0,0);
    setup_nl();
    //ENCAP type neighbour modification 
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_ENCAP;
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);


    //changing mac address in encap feild
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_ENCAP;
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x44\x55\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"changing mac address in encap feild",MAX_STR-1);
    test_print(str,0,0);
    //changing nh type to RCV from ENCAP 
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_RCV;

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"changing type of nexthop",MAX_STR-1);
    test_print(str,-EINVAL,offsetof(vr_nexthop_req,nhr_type));


    //nhr_flags set to 0 i.e. Invalid
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = 0x0;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_ENCAP;
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x44\x55\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"changing nhr_flags to invalid",MAX_STR-1);
    test_print(str,0,0);

    //nhr_flags are changed back to VALID
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_ENCAP;
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x44\x55\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"changing nhr_flags to valid",MAX_STR-1);
    test_print(str,0,0);

    //change in nhr_encap_size 
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =16 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_ENCAP;
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x44\x55\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"changing nhr_flags to valid",MAX_STR-1);
    test_print(str,-EINVAL,offsetof(vr_nexthop_req,nhr_encap_size));

    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_DELETE;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);

    //nhr_flags has NH_FLAG_ENCAP_L2
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_ENCAP_L2;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_ENCAP;
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x44\x55\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"nhr_flags contain NH_FLAG_ENCAP_L2 and nhr_encap_size has a value",MAX_STR-1);
    test_print(str,-EINVAL,offsetof(vr_nexthop_req,nhr_encap_size));

    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_ENCAP_L2;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size = 0;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_ENCAP;

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"nhr_flags contain NH_FLAG_ENCAP_L2 and nhr_encap_size has a value 0 ",MAX_STR-1);
    test_print(str,0,offsetof(vr_nexthop_req,nhr_encap_size));

    //encap_oif_oid is not there 
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id = 2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_ENCAP;
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"encap_oif_oid is wrong ",MAX_STR-1);
    test_print(str,-EINVAL,offsetof(vr_nexthop_req,nhr_encap_size));

    soft_reset();
    //encap_oif_oid has more than the maximum value
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id =  VR_MAX_INTERFACES;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_ENCAP;
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"encap_oif_oid has more than the maximum value ",MAX_STR-1);
    test_print(str,-ENODEV,offsetof(vr_nexthop_req,nhr_encap_oif_id));

    //nhr_flags NH_FLAG_MCAST
    soft_reset();
    add_interface(0);
    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_ENCAP;
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"All fields of vr_nexthop_req are proper and NH_FLAG_MCAST flag is set",MAX_STR-1);
    test_print(str,0,0);

}

int 
tunnel_nexthop_testcases()
{
    vr_nexthop_req nh_req;
    int ret=0,error=0;
    struct in_addr srcip;
    struct in_addr dstip;
    char *str=(char *) malloc(MAX_STR);

    inet_aton("23.23.23.24",&srcip);
    inet_aton("23.23.23.25",&dstip);
    if(!str) {
        printf("Memmory allocation has failed\n");
        exit(1);
    }

    printf("------------------TUNNEL next hop testcases-------------------\n");
    soft_reset();
    add_interface(0);
    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_TUNNEL;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"create next hop request with type:TUNNEL and without specific tunnel type ",MAX_STR-1);
    test_print(str,-EINVAL,offsetof(vr_nexthop_req,nhr_flags));

    //encap_oif_id worng
    soft_reset();
    add_interface(0);
    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_TUNNEL_GRE;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-3;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_TUNNEL;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"NH_FLAG_TUNNEL_GRE testcase with improper encap_oif_id",MAX_STR-1);
    test_print(str,-ENODEV,offsetof(vr_nexthop_req,nhr_encap_oif_id));

    //All fields of vr_next_hop of TUNNEL type are proper GRE
    soft_reset();
    add_interface(0);
    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_TUNNEL_GRE;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_TUNNEL;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"NH_FLAG_TUNNEL_GRE testcase with all proper values",MAX_STR-1);
    test_print(str,0,0);

    //NH_FLAG_TUNNEL_UDP
    soft_reset();
    add_interface(0);
    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_TUNNEL_UDP;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_TUNNEL;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"NH_FLAG_TUNNEL_UDP testcase with all fields of vr_nexthop structure are proper",MAX_STR-1);
    test_print(str,0,0);


    //NH_FLAG_TUNNEL_UDP_MPLS with invalid encap_oif_id
    soft_reset();
    add_interface(0);
    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_TUNNEL_UDP_MPLS;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-3;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_TUNNEL;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"NH_FLAG_TUNNEL_UDP_MPLS testcase with invalid encap_oif_id",MAX_STR-1);
    test_print(str,-ENODEV,offsetof(vr_nexthop_req,nhr_encap_oif_id));


    soft_reset();
    add_interface(0);
    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_TUNNEL_UDP_MPLS;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_TUNNEL;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"NH_FLAG_TUNNEL_UDP_MPLS testcase with proper values",MAX_STR-1);
    test_print(str,0,0);

    //NH_FLAG_TUNNEL_VXLAN  test cases 
    soft_reset();
    add_interface(0);
    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_TUNNEL_VXLAN;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-3;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_TUNNEL;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"NH_FLAG_TUNNEL_VXLAN testcase with invalid encap_oif_id",MAX_STR-1);
    test_print(str,-ENODEV,offsetof(vr_nexthop_req,nhr_encap_oif_id));

    soft_reset();
    add_interface(0);
    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_TUNNEL_VXLAN;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_TUNNEL;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"NH_FLAG_TUNNEL_VXLAN testcase with proper values",MAX_STR-1);
    test_print(str,0,0);
}

int
composite_nexthop_testcases()
{
    vr_nexthop_req nh_req;
    int ret=0,error=0;
    struct in_addr srcip;
    struct in_addr dstip;
    int i=0;	
    char *str=(char *) malloc(MAX_STR);

    inet_aton("23.23.23.24",&srcip);
    inet_aton("23.23.23.25",&dstip);
    if(!str)
    {
        printf("Memmory allocation has failed\n");
        exit(1);
    }

    //COMPOSITE_L3
    soft_reset();
    add_interface(0);
    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_MCAST|NH_FLAG_TUNNEL_VXLAN;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-3;
    nh_req.nhr_type=NH_ENCAP;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);

    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_MCAST|NH_FLAG_TUNNEL_VXLAN;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-4;
    nh_req.nhr_type=NH_ENCAP;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);


    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID| NH_FLAG_MCAST|NH_FLAG_COMPOSITE_L3;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =0 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_COMPOSITE;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_nh_list_size = COMPOSITE_NEXTHOP_LEN;
    nh_req.nhr_label_list_size = COMPOSITE_NEXTHOP_LEN;
    nh_req.nhr_nh_list = calloc(COMPOSITE_NEXTHOP_LEN, sizeof(uint32_t));
    nh_req.nhr_label_list = calloc(COMPOSITE_NEXTHOP_LEN, sizeof(uint32_t));
    for (i = 0; i < COMPOSITE_NEXTHOP_LEN; i++)
    {
        nh_req.nhr_nh_list[i] = NH_TABLE_ENTRIES-4+i;
        if (i < COMPOSITE_NEXTHOP_LEN)
            nh_req.nhr_label_list[i] = VR_MAX_INTERFACES-4+i;
        else
            nh_req.nhr_label_list[i] = (i + 100);

    }

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"NH_COMPOSITE testcase with proper values",MAX_STR-1);
    test_print(str,0,0);

    //NH_FLAG_COMPOSITE_FABRIC testcase
    soft_reset();
    add_interface(0);
    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_MCAST|NH_FLAG_TUNNEL_VXLAN;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-3;
    nh_req.nhr_type=NH_TUNNEL;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_MCAST|NH_FLAG_TUNNEL_VXLAN;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-4;
    nh_req.nhr_type=NH_TUNNEL;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);

    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID| NH_FLAG_MCAST|NH_FLAG_COMPOSITE_FABRIC;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =0 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_COMPOSITE;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_nh_list_size = COMPOSITE_NEXTHOP_LEN;
    nh_req.nhr_label_list_size = COMPOSITE_NEXTHOP_LEN;
    nh_req.nhr_nh_list = calloc(COMPOSITE_NEXTHOP_LEN, sizeof(uint32_t));
    nh_req.nhr_label_list = calloc(COMPOSITE_NEXTHOP_LEN, sizeof(uint32_t));
    for (i = 0; i < COMPOSITE_NEXTHOP_LEN; i++)
    {
        nh_req.nhr_nh_list[i] = NH_TABLE_ENTRIES-4+i;
        if (i < COMPOSITE_NEXTHOP_LEN)
            nh_req.nhr_label_list[i] = VR_MAX_INTERFACES-4+i;
        else
            nh_req.nhr_label_list[i] = (i + 100);

    }

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"NH_FLAG_COMPOSITE_FABRIC testcase with proper values",MAX_STR-1);
    test_print(str,0,0);


    //	NH_FLAG_COMPOSITE_FABRIC test case with nhr_flags has UDP
    soft_reset();
    add_interface(0);
    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_MCAST|NH_FLAG_TUNNEL_UDP;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-3;
    nh_req.nhr_type=NH_TUNNEL;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_MCAST|NH_FLAG_TUNNEL_VXLAN;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-4;
    nh_req.nhr_type=NH_TUNNEL;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_encap=(int8_t *)calloc(1,nh_req.nhr_encap_size);
    nh_req.nhr_encap="\x00\x12\x13\x14\x15\x16\x11\x23\x24\25\26\x27\x08";

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);

    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID| NH_FLAG_MCAST|NH_FLAG_COMPOSITE_FABRIC;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =0 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_COMPOSITE;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_nh_list_size = COMPOSITE_NEXTHOP_LEN;
    nh_req.nhr_label_list_size = COMPOSITE_NEXTHOP_LEN;
    nh_req.nhr_nh_list = calloc(COMPOSITE_NEXTHOP_LEN, sizeof(uint32_t));
    nh_req.nhr_label_list = calloc(COMPOSITE_NEXTHOP_LEN, sizeof(uint32_t));
    for (i = 0; i < COMPOSITE_NEXTHOP_LEN; i++)
    {
        nh_req.nhr_nh_list[i] = NH_TABLE_ENTRIES-4+i;
        if (i < COMPOSITE_NEXTHOP_LEN)
            nh_req.nhr_label_list[i] = VR_MAX_INTERFACES-4+i;
        else
            nh_req.nhr_label_list[i] = (i + 100);

    }

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"NH_FLAG_COMPOSITE_FABRIC testcase with one of the NH has wrong flags",MAX_STR-1);
    test_print(str,-EINVAL,offsetof(vr_nexthop_req,nhr_flags));

    //NH_FLAG_COMPOSITE_L2 testcase 
    soft_reset();
    add_interface(0);
    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));

    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_ENCAP_L2;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =0 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-3;
    nh_req.nhr_type=NH_ENCAP;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);

    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID|NH_FLAG_ENCAP_L2;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =0 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-4;
    nh_req.nhr_type=NH_ENCAP;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);

    sleep(1);
    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID| NH_FLAG_MCAST|NH_FLAG_COMPOSITE_L2;
    nh_req.nhr_encap_oif_id = VR_MAX_INTERFACES-2;
    nh_req.nhr_encap_size =0 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=NH_TABLE_ENTRIES-2;
    nh_req.nhr_type=NH_COMPOSITE;
    nh_req.nhr_tun_sip=srcip.s_addr;
    nh_req.nhr_tun_dip=dstip.s_addr;
    nh_req.nhr_tun_sport = htons(8000);
    nh_req.nhr_tun_dport = htons(8000);
    nh_req.nhr_nh_list_size = COMPOSITE_NEXTHOP_LEN;
    nh_req.nhr_label_list_size = COMPOSITE_NEXTHOP_LEN;
    nh_req.nhr_nh_list = calloc(COMPOSITE_NEXTHOP_LEN, sizeof(uint32_t));
    nh_req.nhr_label_list = calloc(COMPOSITE_NEXTHOP_LEN, sizeof(uint32_t));
    for (i = 0; i < COMPOSITE_NEXTHOP_LEN; i++)
    {
        nh_req.nhr_nh_list[i] = NH_TABLE_ENTRIES-4+i;
        if (i < COMPOSITE_NEXTHOP_LEN)
            nh_req.nhr_label_list[i] = VR_MAX_INTERFACES-4+i;
        else
            nh_req.nhr_label_list[i] = (i + 100);

    }

    ret = sandesh_encode(&nh_req, "vr_nexthop_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"NH_FLAG_COMPOSITE_L2 testcase with proper values",MAX_STR-1);
    test_print(str,0,0);

    //TODO NH_FLAG_COMPOSITE_MULTI_PROTO

}
int 
nexthop_testcases()
{
    int ret;
    int opt;
    int ind;

    soft_reset();
    setup_environment(0);
    printf("---------------NEIGHBOUR ADD/UPDATE testcases----------\n");
    rcv_nexthop_testcases();
    encap_nexthop_testcases();
    tunnel_nexthop_testcases();
    composite_nexthop_testcases();
    cleanup();
}
