#include"vr_tests.h"
static int print_message=1;
static void 
setup_mpls_environment()
{

    //create tap interface and attach to vif
    soft_reset();
    setup_nl();
    setup_environment(0);
    //create nexthops for the VXLAN 
    add_nh(VR_MAX_INTERFACES-2, NH_TABLE_ENTRIES-2);
}
int 
create_mpls_req(unsigned int op,uint32_t nhid,uint32_t label,char *str,int expected_ret,int offset)
{
    vr_mpls_req mpls_req;
    int ret=0, error=0;

    memset(&mpls_req,0,sizeof(vr_mpls_req));
    mpls_req.h_op = op;
    mpls_req.mr_label = label;
    mpls_req.mr_nhid=  nhid;

    setup_nl();

    ret = sandesh_encode(&mpls_req, "vr_mpls_req", vr_find_sandesh_info,
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
create_mpls_test_cases()
{
    char str[MAX_STR];

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mpls ADD test case with nhid has wrong value",MAX_STR-1);
    /*1:op 2:nhid 3:mpls label 4:str to be printed 5:expected return value 6:expected offset*/
    create_mpls_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-3,VR_MAX_LABELS-2,str,-EINVAL,offsetof(vr_mpls_req,mr_nhid));

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mpls ADD test case with  mpls label has wrong",MAX_STR-1);
    /*1:op 2:nhid 3:mpls label 4:str to be printed 5:expected return value 6:expected offset*/
    create_mpls_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-2,NH_TABLE_ENTRIES-2,str,-EINVAL,offsetof(vr_mpls_req,mr_label));

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mpls ADD test case with proper mpls label and nhid",MAX_STR-1);
    /*1:op 2:nhid 3:mpls label 4:str to be printed 5:expected return value 6:expected offset*/
    create_mpls_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-2,VR_MAX_LABELS-2,str,0,0);
}
void 
get_mpls_test_cases()
{
    char str[MAX_STR];

    memset(str,0,sizeof(str));
    print_message=0;
    strncpy(str,"mpls ADD test case with all proper values",MAX_STR-1);
    /*1:op 2:nhid 3:mpls label 4:str to be printed 5:expected return value 6:expected offset*/
    create_mpls_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-2,VR_MAX_LABELS-2,str,0,0);

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mpls GET test case with invalid label ",MAX_STR-1);
    /*1:op 2:nhid 3:mpls label 4:str to be printed 5:expected return value 6:expected offset*/
    create_mpls_req(SANDESH_OP_GET,NH_TABLE_ENTRIES-2,VR_MAX_LABELS-3,str,-ENOENT,offsetof(vr_mpls_req,mr_label));

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mpls GET test case with all proper values",MAX_STR-1);
    /*1:op 2:nhid 3:mpls label 4:str to be printed 5:expected return value 6:expected offset*/
    create_mpls_req(SANDESH_OP_GET,NH_TABLE_ENTRIES-2,VR_MAX_LABELS-2,str,0,0);
}
void 
delete_mpls_test_cases()
{
    char str[MAX_STR];

    memset(str,0,sizeof(str));
    print_message=0;
    strncpy(str,"mpls ADD test case with all proper values",MAX_STR-1);
    /*1:op 2:nhid 3:mpls label 4:str to be printed 5:expected return value 6:expected offset*/
    create_mpls_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-2,VR_MAX_LABELS-2,str,0,0);

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mpls DELTE test case with nhid is not there",MAX_STR-1);
    /*1:op 2:nhid 3:mpls label 4:str to be printed 5:expected return value 6:expected offset*/
    create_mpls_req(SANDESH_OP_DELETE,NH_TABLE_ENTRIES-3,VR_MAX_LABELS-2,str,0,0);

    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mpls DELTE test case with label feild > VR_MAX_LABELS",MAX_STR-1);
    /*1:op 2:nhid 3:mpls label 4:str to be printed 5:expected return value 6:expected offset*/
    create_mpls_req(SANDESH_OP_DELETE,NH_TABLE_ENTRIES-2,VR_MAX_LABELS+2,str,-EINVAL,offsetof(vr_mpls_req,mr_label));


    memset(str,0,sizeof(str));
    print_message=1;
    strncpy(str,"mpls DELTE test case with proper nhid",MAX_STR-1);
    /*1:op 2:nhid 3:mpls label 4:str to be printed 5:expected return value 6:expected offset*/
    create_mpls_req(SANDESH_OP_DELETE,NH_TABLE_ENTRIES-2,VR_MAX_LABELS-2,str,0,0);
}

void 
mpls_test_cases()
{
    setup_mpls_environment();
    create_mpls_test_cases();
    get_mpls_test_cases();
    delete_mpls_test_cases();
    cleanup();
}
