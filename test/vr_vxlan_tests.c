#include"vr_tests.h"
static int print_message=1;
static void 
setup_vxlan_environment()
{

    //create tap interface and attach to vif
    soft_reset();
    setup_nl();
    setup_environment(0);
    //create nexthops for the VXLAN 
    add_nh(VR_MAX_INTERFACES-2, NH_TABLE_ENTRIES-2);
}
int 
create_vx_lan_req(unsigned int op,uint32_t nhid,uint32_t vnid,char *str,int expected_ret,int offset)
{
    vr_vxlan_req vxlan_req;
    int ret=0, error=0;

    memset(&vxlan_req,0,sizeof(vr_vxlan_req));
    vxlan_req.h_op = op;
    vxlan_req.vxlanr_vnid = vnid;
    vxlan_req.vxlanr_nhid=  nhid;

    setup_nl();

    ret = sandesh_encode(&vxlan_req, "vr_vxlan_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    if(print_message)
        test_print(str,expected_ret,offset);
}
void 
create_vxlan_test_cases()
{
    char str[MAX_STR];

    memset(str,0,sizeof(str));
    print_message=1;
    /*1:op 2:nhid 3:vnid 4:str to be printed 5:expected return value 6:expected offset*/
    strncpy(str,"vxlan ADD test case nhid has wrong value",MAX_STR-1);
    create_vx_lan_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-3,NH_TABLE_ENTRIES-2,str,-EINVAL,offsetof(vr_vxlan_req,vxlanr_nhid));

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"vxlan ADD test case with proper vnid and nhid",MAX_STR-1);
    /*1:op 2:nhid 3:vnid 4:str to be printed 5:expected return value 6:expected offset*/
    create_vx_lan_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-2,NH_TABLE_ENTRIES-2,str,0,0);

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"vxlan ADD test case with proper vnid and nhid",MAX_STR-1);
    /*1:op 2:nhid 3:vnid 4:str to be printed 5:expected return value 6:expected offset*/
    create_vx_lan_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-2,NH_TABLE_ENTRIES-2,str,0,0);
}
void 
get_vxlan_test_cases()
{
    char str[MAX_STR];

    memset(str,0,sizeof(str));
    print_message=0;
    strncpy(str,"vxlan ADD test case with all proper values",MAX_STR-1);
    /*1:op 2:nhid 3:vnid 4:str to be printed 5:expected return value 6:expected offset*/
    create_vx_lan_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-2,NH_TABLE_ENTRIES-2,str,0,0);

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"vxlan GET test case with vnid is not there",MAX_STR-1);
    /*1:op 2:nhid 3:vnid 4:str to be printed 5:expected return value 6:expected offset*/
    create_vx_lan_req(SANDESH_OP_GET,0,NH_TABLE_ENTRIES-10,str,-ENOENT,offsetof(vr_vxlan_req,vxlanr_vnid));

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"vxlan GET test case with all proper values",MAX_STR-1);
    /*1:op 2:nhid 3:vnid 4:str to be printed 5:expected return value 6:expected offset*/
    create_vx_lan_req(SANDESH_OP_GET,NH_TABLE_ENTRIES-2,NH_TABLE_ENTRIES-2,str,0,0);
}
void 
delete_vxlan_test_cases()
{
    char str[MAX_STR];

    memset(str,0,sizeof(str));
    print_message=0;
    strncpy(str,"vxlan ADD test case with all proper values",MAX_STR-1);
    /*1:op 2:nhid 3:vnid 4:str to be printed 5:expected return value 6:expected offset*/
    create_vx_lan_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-2,NH_TABLE_ENTRIES-2,str,0,0);

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"vxlan DELTE test case with nhid is not there",MAX_STR-1);
    /*1:op 2:nhid 3:vnid 4:str to be printed 5:expected return value 6:expected offset*/
    create_vx_lan_req(SANDESH_OP_DELETE,NH_TABLE_ENTRIES-3,NH_TABLE_ENTRIES-2,str,0,0);

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"vxlan DELTE test case with proper nhid",MAX_STR-1);
    /*1:op 2:nhid 3:vnid 4:str to be printed 5:expected return value 6:expected offset*/
    create_vx_lan_req(SANDESH_OP_DELETE,NH_TABLE_ENTRIES-2,NH_TABLE_ENTRIES-2,str,0,0);
}

void vxlan_test_cases()
{
    setup_vxlan_environment();
    create_vxlan_test_cases();
    get_vxlan_test_cases();
    delete_vxlan_test_cases();
    cleanup();
}
