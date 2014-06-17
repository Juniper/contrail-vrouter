#include"vr_tests.h"
static int print_message=1;
void 
setup_mirror_environment()
{
    //create tap interface and attach to vif
    soft_reset();
    setup_nl();
    setup_environment(0);
    //create nexthops for the VXLAN 
    add_nh(VR_MAX_INTERFACES-2, NH_TABLE_ENTRIES-2);
}
int 
create_mirror_req(unsigned int op,uint32_t nhid,uint32_t index,char *str,int expected_ret,int offset)
{
    vr_mirror_req mirror_req;
    int ret=0, error=0;

    memset(&mirror_req,0,sizeof(vr_mirror_req));
    mirror_req.h_op = op;
    mirror_req.mirr_index = index;
    mirror_req.mirr_nhid=  nhid;

    setup_nl();

    ret = sandesh_encode(&mirror_req, "vr_mirror_req", vr_find_sandesh_info,
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
create_mirror_test_cases()
{
    char str[MAX_STR];

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mirror ADD test case with nhid has wrong value",MAX_STR-1);
    /*1:op 2:nhid 3:mirror index 4:str to be printed 5:expected return value 6:expected offset*/
    create_mirror_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-3,VR_MAX_MIRROR_INDICES-2,str,-EINVAL,offsetof(vr_mirror_req,mirr_nhid));

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mirror ADD test case with  mirror index has wrong",MAX_STR-1);
    /*1:op 2:nhid 3:mirror index 4:str to be printed 5:expected return value 6:expected offset*/
    create_mirror_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-2,NH_TABLE_ENTRIES-2,str,-EINVAL,offsetof(vr_mirror_req,mirr_index));

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mirror ADD test case with proper mirror index and nhid",MAX_STR-1);
    /*1:op 2:nhid 3:mirror index 4:str to be printed 5:expected return value 6:expected offset*/
    create_mirror_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-2,VR_MAX_MIRROR_INDICES-2,str,0,0);
}
void 
get_mirror_test_cases()
{
    char str[MAX_STR];

    memset(str,0,sizeof(str));
    print_message=0;
    strncpy(str,"mirror ADD test case with all proper values",MAX_STR-1);
    /*1:op 2:nhid 3:mirror index 4:str to be printed 5:expected return value 6:expected offset*/
    create_mirror_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-2,VR_MAX_MIRROR_INDICES-2,str,0,0);

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mirror GET test case with invalid index ",MAX_STR-1);
    /*1:op 2:nhid 3:mirror index 4:str to be printed 5:expected return value 6:expected offset*/
    create_mirror_req(SANDESH_OP_GET,NH_TABLE_ENTRIES-2,VR_MAX_MIRROR_INDICES-3,str,-ENOENT,offsetof(vr_mirror_req,mirr_index));

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mirror GET test case with all proper values",MAX_STR-1);
    /*1:op 2:nhid 3:mirror index 4:str to be printed 5:expected return value 6:expected offset*/
    create_mirror_req(SANDESH_OP_GET,NH_TABLE_ENTRIES-2,VR_MAX_MIRROR_INDICES-2,str,0,0);
}
void 
delete_mirror_test_cases()
{
    char str[MAX_STR];

    memset(str,0,sizeof(str));
    print_message=0;
    //create and then delete
    strncpy(str,"mirror ADD test case with all proper values",MAX_STR-1);
    /*1:op 2:nhid 3:mirror index 4:str to be printed 5:expected return value 6:expected offset*/
    create_mirror_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-2,VR_MAX_MIRROR_INDICES-2,str,0,0);

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mirror DELTE test case with nhid is not there",MAX_STR-1);
    /*1:op 2:nhid 3:mirror index 4:str to be printed 5:expected return value 6:expected offset*/
    create_mirror_req(SANDESH_OP_DELETE,NH_TABLE_ENTRIES-3,VR_MAX_MIRROR_INDICES-2,str,0,0);


    /*IT has been deleted without proper field in nhid so adding it again*/

    memset(str,0,sizeof(str));
    print_message=0;
    strncpy(str,"mirror ADD test case with all proper values",MAX_STR-1);
    /*1:op 2:nhid 3:mirror index 4:str to be printed 5:expected return value 6:expected offset*/
    create_mirror_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-2,VR_MAX_MIRROR_INDICES-2,str,0,0);


    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mirror DELTE test case with index feild > VR_MAX_MIRROR_INDICES",MAX_STR-1);
    /*1:op 2:nhid 3:mirror index 4:str to be printed 5:expected return value 6:expected offset*/
    create_mirror_req(SANDESH_OP_DELETE,NH_TABLE_ENTRIES-2,VR_MAX_MIRROR_INDICES+2,str,-EINVAL,offsetof(vr_mirror_req,mirr_index));


    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mirror DELTE test case with proper nhid",MAX_STR-1);
    /*1:op 2:nhid 3:mirror index 4:str to be printed 5:expected return value 6:expected offset*/
    create_mirror_req(SANDESH_OP_DELETE,NH_TABLE_ENTRIES-2,VR_MAX_MIRROR_INDICES-2,str,0,0);
}

void 
mirror_test_cases()
{
    setup_mirror_environment();
    create_mirror_test_cases();
    get_mirror_test_cases();
    delete_mirror_test_cases();
    cleanup();
}
