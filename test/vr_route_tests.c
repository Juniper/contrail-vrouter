#include"vr_tests.h"
static int print_message=1;
int 
add_nh(int encap_id,int nhr_id)
{
    int ret=0,error=0,attr_len;
    vr_nexthop_req nh_req;
    char *str=(char *) malloc(MAX_STR);

    if(!str) {
        printf("Memmory allocation has failed\n");
        exit(1);
    }

    attr_len = nl_get_attr_hdr_size();


    setup_nl();
    memset(&nh_req,0,sizeof(nh_req));
    nh_req.h_op = SANDESH_OP_ADD;
    nh_req.nhr_flags = NH_FLAG_VALID;
    nh_req.nhr_encap_oif_id = encap_id;
    nh_req.nhr_encap_size =14 ;
    nh_req.nhr_encap_family = ETH_P_ARP;
    nh_req.nhr_family=AF_INET;
    nh_req.nhr_vrf = 0;
    nh_req.nhr_id=nhr_id;
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
}
static void 
setup_route_environment()
{

    //create tap interface and attach to vif
    soft_reset();
    setup_nl();
    setup_environment(0);
    //create nexthops for the route 
    add_nh(VR_MAX_INTERFACES-2, NH_TABLE_ENTRIES-2);
}
int create_and_send_rt_add_structure(unsigned int op, int family, unsigned int prefix, unsigned int p_len,
	unsigned int nh_id, unsigned int vrf, int label,
	unsigned int rt_type, unsigned int src, char *eth, uint32_t replace_plen,int proxy_set,int mac_size,vr_route_req *rt_req,char *str,int expected_ret,int offset)
{
    int ret=0,error=0;


    setup_nl();
    rt_req->rtr_family = family;
    rt_req->rtr_vrf_id = vrf;
    rt_req->rtr_rid = 0;
    rt_req->h_op = op;
    switch (rt_req->h_op) 
    {
        default:
            rt_req->rtr_nh_id = nh_id;
            rt_req->rtr_prefix = prefix;
            rt_req->rtr_prefix_len = p_len;
            rt_req->rtr_label_flags = 0;
            rt_req->rtr_rt_type = rt_type;
            rt_req->rtr_replace_plen = replace_plen;

            if (proxy_set)
                rt_req->rtr_label_flags |= VR_RT_HOSTED_FLAG;

            if (family == AF_INET) 
            {
                if (rt_type == RT_UCAST) {
                    rt_req->rtr_src = 0;
                } else {
                    rt_req->rtr_src = src;
                }
                if (label != -1) {
                    rt_req->rtr_label = label;
                    rt_req->rtr_label_flags |= VR_RT_LABEL_VALID_FLAG;
                }
            } 
            else {
                if(mac_size){
                    rt_req->rtr_mac = calloc(1,VR_ETHER_ALEN);
                    rt_req->rtr_mac_size = VR_ETHER_ALEN;
                    if(rt_req->rtr_mac)
                        memcpy(rt_req->rtr_mac,eth, VR_ETHER_ALEN);
                    else
                        exit(1);
                }
                if (label != -1) {
                    rt_req->rtr_label = label;
                    rt_req->rtr_label_flags |= VR_RT_LABEL_VALID_FLAG;
                }
            }
            break;
    }
    ret = sandesh_encode(rt_req, "vr_route_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error)
    {
        return ret;
    }
    ret=send_recive_check(ret);
    if(print_message)
        test_print(str,expected_ret,offset);
}
int
add_route_test_cases()
{
    vr_interface_req vr_req;
    vr_route_req rt_req;
    char mac[VR_ETHER_ALEN]="\x00\x12\x13\x14\x15\x16";
    char *str=(char *) malloc(MAX_STR_SIZE);

    if(!str) {
        printf("Memmory allocation has failed\n");
        exit(1);
    }

    setup_route_environment();
    //rtr_family has a wrong value
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE addition testcase with rtr_family is neither AF_INET nor AF_BRIDGE",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_ADD,3,0x17171702,32,NH_TABLE_ENTRIES-2,0,0, RT_UCAST,0x17171701,mac,0,0,VR_ETHER_ALEN,&rt_req,str,-ENOENT,offsetof(vr_route_req,rtr_family));
    //all values are proper
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE addition testcase with all proper values",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_ADD,AF_INET,0x17171702,32,NH_TABLE_ENTRIES-2,0,0, RT_UCAST,0x17171701,mac,0,0,VR_ETHER_ALEN,&rt_req,str,0,0);

    //rtr_rt_type has wrong value
    soft_reset();
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE addition testcase with rt_type  ",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_ADD,AF_INET,0x17171702,32,NH_TABLE_ENTRIES-2,0,0, RT_MAX,0x17171701,mac,0,0,VR_ETHER_ALEN,&rt_req,str,-EINVAL,offsetof(vr_route_req,rtr_rt_type));

    //rtr_vrf_id has wrong
    soft_reset();
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE addition testcase with rtr_vrf_id",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_ADD,AF_INET,0x17171702,32,NH_TABLE_ENTRIES-2,VR_MAX_VRFS+1,0, RT_UCAST,0x17171701,mac,0,0,VR_ETHER_ALEN,&rt_req,str,-EINVAL,offsetof(vr_route_req,rtr_vrf_id));

    //rtr_prefix_len has a wrong value 
    soft_reset();
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE addition testcase with rtr_prefix_len",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_ADD,AF_INET,0x17171702,33,NH_TABLE_ENTRIES-2,0,0, RT_UCAST,0x17171701,mac,0,0,VR_ETHER_ALEN,&rt_req,str,-EINVAL,offsetof(vr_route_req,rtr_prefix_len));

    //AF_INET and MCAST
    cleanup();
    setup_route_environment();
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE,MCAST addition testcase with proper values",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_ADD,AF_INET,0x17171702,32,NH_TABLE_ENTRIES-2,0,0, RT_MCAST,0x17171701,mac,0,0,VR_ETHER_ALEN,&rt_req,str,0,0);

    // rtr_family AF_BRIDGE
    cleanup();
    setup_route_environment();
    memset(&rt_req,0,sizeof(vr_route_req));
    strncpy(str,"ROUTE addition testcase with rtr_mac_size=0 ",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_ADD,AF_BRIDGE,0x17171702,32,NH_TABLE_ENTRIES-2,0,0, RT_UCAST,0x17171701,mac,0,0,0,&rt_req,str,-EINVAL,offsetof(vr_route_req,rtr_mac_size));

    cleanup();
    setup_route_environment();
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE addition testcase with proper values except rtr_vrf_id",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_ADD,AF_BRIDGE,0x17171702,32,NH_TABLE_ENTRIES-2,VR_MAX_VRFS+1,0, RT_UCAST,0x17171701,mac,0,0,VR_ETHER_ALEN,&rt_req,str,-EINVAL,offsetof(vr_route_req,rtr_vrf_id));

    cleanup();
    setup_route_environment();
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE addition testcase with proper values",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_ADD,AF_BRIDGE,0x17171702,32,NH_TABLE_ENTRIES-2,0,0, RT_UCAST,0x17171701,mac,0,0,VR_ETHER_ALEN,&rt_req,str,0,0);

    cleanup();
    setup_route_environment();
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE addition testcase with label proper values",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_ADD,AF_BRIDGE,0x17171702,32,NH_TABLE_ENTRIES-2,0,/*label*/1, RT_UCAST,0x17171701,mac,0,0,VR_ETHER_ALEN,&rt_req,str,0,0);


}
void 
get_route_test_cases()
{
    int ret=0,error=0;
    vr_route_req rt_req;
    char mac[VR_ETHER_ALEN]="\x00\x12\x13\x14\x15\x16";
    char *str=(char *) malloc(MAX_STR_SIZE);

    printf("----GET route testcase----\n",__FILE__,__LINE__);

    if(!mac) {
        printf("mallo has failed file name:%s,lineno: %d\n",__FILE__,__LINE__);
        exit(1);
    }	

    cleanup();
    setup_route_environment();

    //creating a RT_UCAST route
    print_message=0;
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE addition testcase with all proper values",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_ADD,AF_INET,0x17171702,32,NH_TABLE_ENTRIES-2,0,0, RT_UCAST,0x17171701,mac,0,1,VR_ETHER_ALEN,&rt_req,str,0,0);

    //trying to get route from a table which is not there 
    print_message=1;
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE UCAST  get testcase with rt_type contains a wrong value",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_GET,AF_INET,0x17171702,32,NH_TABLE_ENTRIES-2,0,0,RT_MAX,0x17171701,mac,0,0,VR_ETHER_ALEN,&rt_req,str,-ENOENT,offsetof(vr_route_req,rtr_rt_type));

    //al ld=feilds are proper 
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE UCAST get testcase with all proper values",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_GET,AF_INET,0x17171702,32,NH_TABLE_ENTRIES-2,0,0, RT_UCAST,0x17171701,mac,0,1,VR_ETHER_ALEN,&rt_req,str,0,0);

    //create multicast route
    cleanup();
    setup_route_environment();

    print_message=0;
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE MAST addition testcase with all proper values",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_ADD,AF_INET,0x17171702,32,NH_TABLE_ENTRIES-2,0,0, RT_MCAST,0x17171701,mac,0,1,VR_ETHER_ALEN,&rt_req,str,0,0);


    print_message=1;
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE MAST addition testcase with all proper values",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_GET,AF_INET,0x17171702,32,NH_TABLE_ENTRIES-2,0,0, RT_MCAST,0x17171701,mac,0,1,VR_ETHER_ALEN,&rt_req,str,0,0);
}
void 
delete_route_test_cases()
{

    int ret=0,error=0;
    vr_route_req rt_req;
    char mac[VR_ETHER_ALEN]="\x00\x12\x13\x14\x15\x16";
    char *str=(char *) malloc(MAX_STR_SIZE);

    printf("----DELETE route testcase----\n",__FILE__,__LINE__);

    if(!mac) {
        printf("mallo has failed file name:%s,lineno: %d\n",__FILE__,__LINE__);
        exit(1);
    }

    cleanup();
    setup_route_environment();

    //creating a RT_UCAST route
    print_message=0;
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE addition testcase with all proper values",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_ADD,AF_INET,0x17171702,32,NH_TABLE_ENTRIES-2,0,0,RT_UCAST,0x17171701,mac,0,1,VR_ETHER_ALEN,&rt_req,str,0,0);


    //DEL test case with 

    print_message=1;
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE delete testcase with all proper values",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_DELETE,AF_INET,0x17171702,32,NH_TABLE_ENTRIES-2,0,0,RT_UCAST,0x17171701,mac,24,1,VR_ETHER_ALEN,&rt_req,str,0,0);

    print_message=1;
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE delete testcase with rtr_family==3 i.e. niether INET nor BRIDGE",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_DELETE,3,0x17171702,32,NH_TABLE_ENTRIES-2,0,0,RT_UCAST,0x17171701,mac,24,1,VR_ETHER_ALEN,&rt_req,str,-ENOENT,offsetof(vr_route_req,rtr_family));

    print_message=1;
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE delete testcase with rtr_prefix_len=33 ",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_DELETE,AF_INET,0x17171702,33,NH_TABLE_ENTRIES-2,0,0,RT_UCAST,0x17171701,mac,0,1,VR_ETHER_ALEN,&rt_req,str,-EINVAL,offsetof(vr_route_req,rtr_prefix_len));

    print_message=1;
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE delete testcase with rtr_vrf_id=4097 ",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_DELETE,AF_INET,0x17171702,32,NH_TABLE_ENTRIES-2,VR_MAX_VRFS+1,0,RT_UCAST,0x17171701,mac,0,1,VR_ETHER_ALEN,&rt_req,str,-EINVAL,offsetof(vr_route_req,rtr_vrf_id));


    print_message=1;
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE delete testcase with rtr_type is neither UCAST nor MCAST ",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_DELETE,AF_INET,0x17171702,32,NH_TABLE_ENTRIES-2,0,0,RT_MAX,0x17171701,mac,0,1,VR_ETHER_ALEN,&rt_req,str,-EINVAL,offsetof(vr_route_req,rtr_rt_type));

    print_message=1;
    memset(&rt_req,0,sizeof(vr_route_req));
    memset(str,0,MAX_STR_SIZE);
    strncpy(str,"ROUTE delete testcase with rtr_nh_id not there",MAX_STR-1);
    create_and_send_rt_add_structure(SANDESH_OP_DELETE,AF_INET,0x17171702,32,NH_TABLE_ENTRIES-3,0,0,RT_UCAST,0x17171701,mac,0,1,VR_ETHER_ALEN,&rt_req,str,-ENOENT,offsetof(vr_route_req,rtr_nh_id));

}
void
vr_route_testcases()
{
    soft_reset();
    add_route_test_cases();
    get_route_test_cases();
    delete_route_test_cases();
    cleanup();
}
