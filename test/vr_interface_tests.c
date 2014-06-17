#include"vr_tests.h"
int
add_interface_to_vif()
{
        vr_interface_req vr_req;
        int ret=0,error=0;
        char *str=(char *) malloc(MAX_STR);

        if(!str) {
                printf("Memmory allocation has failed\n");
                exit(1);
        }

        /*
         *
         *Test case with all the values are proper
         * 
         */    
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
        test_print(str,0,0);
        cleanup();

        /*
         *
         * test case with vifr_idx is wrong i.e. more than VR_MAX_INTERFACES
         */

        setup_nl();
        system("ip tuntap add dev taptest mode tap");
        sleep(1);
        memset(&vr_req,0,sizeof(vr_req));
        vr_req.h_op=SANDESH_OP_ADD;
        vr_req.vifr_type=VIF_TYPE_VIRTUAL;
        vr_req.vifr_idx= VR_MAX_INTERFACES+1 ;//this feild is worng 
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
        strncpy(str,"vifr_idx is more than VR_MAX_INTERFACES,",MAX_STR-1);
        test_print(str,-EINVAL,offsetof(vr_interface_req,vifr_idx));
        cleanup();

        /*
         *
         * 
         *         test case with vifr_type is wrong i.e.>=VIF_TYPE_MAX 
         *
         */

        setup_nl();
        system("ip tuntap add dev taptest mode tap");
        sleep(1);
        memset(&vr_req,0,sizeof(vr_req));
        vr_req.h_op=SANDESH_OP_ADD;
        vr_req.vifr_type=VIF_TYPE_MAX+1;//this feild is worng
        vr_req.vifr_idx= VR_MAX_INTERFACES-2;
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
        strncpy(str,"vifr_type  field is > VIF_TYPE_MAX",MAX_STR-1);
        test_print(str,-EINVAL,offsetof(vr_interface_req,vifr_type));
        cleanup();


        /*
         *
         *
         *         test case with vifr_mac_size is more than 6 
         *
         */

        setup_nl();
        system("ip tuntap add dev taptest mode tap");
        sleep(1);
        memset(&vr_req,0,sizeof(vr_req));
        vr_req.h_op=SANDESH_OP_ADD;
        vr_req.vifr_type=VIF_TYPE_VIRTUAL;
        vr_req.vifr_idx= VR_MAX_INTERFACES-2;
        vr_req.vifr_os_idx=if_nametoindex("taptest");
        vr_req.vifr_mac_size=7;
        vr_req.vifr_mac="\x00\x12\x13\x14\x15\x16";

        ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
                        (nl_get_buf_ptr(cl) + attr_len),
                        (nl_get_buf_len(cl) - attr_len), &error);

        if ((ret <= 0) || error) {
                return ret;
        }
        ret=send_recive_check(ret);
        memset(str,0,MAX_STR);
        strncpy(str,"vifr_mac_size feild is more than 7",MAX_STR-1);
        test_print(str,-EINVAL,offsetof(vr_interface_req,vifr_mac_size));
        cleanup();

        /*
         *     
         *MAC is empty
         setup_nl();
         system("ip tuntap add dev taptest mode tap");
         sleep(1);
         memset(&vr_req,0,sizeof(vr_req));
         vr_req.h_op=SANDESH_OP_ADD;
         vr_req.vifr_type=VIF_TYPE_VIRTUAL;
         vr_req.vifr_idx= VR_MAX_INTERFACES-2;
         vr_req.vifr_os_idx=if_nametoindex("taptest");
         vr_req.vifr_mac_size=6;

         ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
         (nl_get_buf_ptr(cl) + attr_len),
         (nl_get_buf_len(cl) - attr_len), &error);

         if ((ret <= 0) || error) {
         return ret;
         }
         ret=send_recive_check(ret);
         memset(str,0,MAX_STR);
         strncpy(str,"vifr_mac has empty string",MAX_STR-1);
         test_print(str,-EINVAL,offsetof(vr_interface_req,vifr_mac));
         exit(1);
         cleanup();
         */

        /*
         *
         *changing interface MTU(inetrface parameter) after addition      
         *
         */
        system("ip tuntap add dev taptest mode tap");
        sleep(1);

        setup_nl();
        memset(&vr_req,0,sizeof(vr_req));
        vr_req.h_op=SANDESH_OP_ADD;
        vr_req.vifr_type=VIF_TYPE_VIRTUAL;
        vr_req.vifr_idx= VR_MAX_INTERFACES-2 ;
        vr_req.vifr_os_idx=if_nametoindex("taptest");
        vr_req.vifr_mac_size=6;
        vr_req.vifr_mtu=1500;
        vr_req.vifr_mac="\x00\x12\x13\x14\x15\x16";

        ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
                        (nl_get_buf_ptr(cl) + attr_len),
                        (nl_get_buf_len(cl) - attr_len), &error);

        if ((ret <= 0) || error) {
                return ret;
        }
        ret=send_recive_check(ret);

        setup_nl();
        memset(&vr_req,0,sizeof(vr_req));
        vr_req.h_op=SANDESH_OP_ADD;
        vr_req.vifr_type=VIF_TYPE_VIRTUAL;
        vr_req.vifr_idx= VR_MAX_INTERFACES-2 ;
        vr_req.vifr_os_idx=if_nametoindex("taptest");
        vr_req.vifr_mac_size=6;
        vr_req.vifr_mtu=1400;
        vr_req.vifr_mac="\x00\x12\x13\x14\x15\x16";

        ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
                        (nl_get_buf_ptr(cl) + attr_len),
                        (nl_get_buf_len(cl) - attr_len), &error);

        if ((ret <= 0) || error) {
                return ret;
        }
        ret=send_recive_check(ret);

        memset(str,0,MAX_STR);
        strncpy(str,"Interface MTU change ",MAX_STR-1);
        test_print(str,0,0);
        cleanup();
        /*
         *     
         *     VHOST interface addition    
         *                 
         */    
        system("ip tuntap add dev taptest mode tap");
        sleep(1);
        setup_nl();
        memset(&vr_req,0,sizeof(vr_req));
        vr_req.h_op=SANDESH_OP_ADD;
        vr_req.vifr_type=VIF_TYPE_PHYSICAL;
        vr_req.vifr_idx= VR_MAX_INTERFACES-2 ;
        vr_req.vifr_os_idx=if_nametoindex("taptest");
        vr_req.vifr_mac_size=6;
        vr_req.vifr_mtu=1500;
        vr_req.vifr_mac="\x00\x12\x13\x14\x15\x16";

        ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
                        (nl_get_buf_ptr(cl) + attr_len),
                        (nl_get_buf_len(cl) - attr_len), &error);

        if ((ret <= 0) || error) {
                return ret;
        }
        ret=send_recive_check(ret);

        system("vif --create vhost0 --mac 00:12:13:14:15:16");
        sleep(1);
        setup_nl();
        memset(&vr_req,0,sizeof(vr_req));
        vr_req.h_op=SANDESH_OP_ADD;
        vr_req.vifr_type=VIF_TYPE_HOST;
        vr_req.vifr_idx= VR_MAX_INTERFACES-3 ;
        vr_req.vifr_os_idx=if_nametoindex("vhost0");
        vr_req.vifr_cross_connect_idx=if_nametoindex("taptest");
        vr_req.vifr_mac_size=6;
        vr_req.vifr_mtu=1500;
        vr_req.vifr_mac="\x00\x12\x13\x14\x15\x16";

        ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
                        (nl_get_buf_ptr(cl) + attr_len),
                        (nl_get_buf_len(cl) - attr_len), &error);

        if ((ret <= 0) || error) {
                return ret;
        }
        ret=send_recive_check(ret);
        memset(str,0,MAX_STR);
        strncpy(str,"VHOST interface addition ",MAX_STR-1);
        test_print(str,0,0);
        cleanup();
        /*
         *
         *       PHYSICAL interface addition
         *
         */
        system("ip tuntap add dev taptest mode tap");
        sleep(1);
        setup_nl();
        memset(&vr_req,0,sizeof(vr_req));
        vr_req.h_op=SANDESH_OP_ADD;
        vr_req.vifr_type=VIF_TYPE_PHYSICAL;
        vr_req.vifr_idx= VR_MAX_INTERFACES-2 ;
        vr_req.vifr_os_idx=if_nametoindex("taptest");
        vr_req.vifr_mac_size=6;
        vr_req.vifr_mtu=1500;
        vr_req.vifr_mac="\x00\x12\x13\x14\x15\x16";

        ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
                        (nl_get_buf_ptr(cl) + attr_len),
                        (nl_get_buf_len(cl) - attr_len), &error);

        if ((ret <= 0) || error) {
                return ret;
        }
        ret=send_recive_check(ret);
        memset(str,0,MAX_STR);
        strncpy(str,"PHYSICAL interface addition ",MAX_STR-1);
        test_print(str,0,0);
        cleanup();
        /*
         *
         *       AGENT interface addition
         *
         */
        system("ip tuntap add dev taptest mode tap");
        sleep(1);
        setup_nl();
        memset(&vr_req,0,sizeof(vr_req));
        vr_req.h_op=SANDESH_OP_ADD;
        vr_req.vifr_type=VIF_TYPE_AGENT;
        vr_req.vifr_idx= VR_MAX_INTERFACES-2 ;
        vr_req.vifr_os_idx=if_nametoindex("taptest");
        vr_req.vifr_mac_size=6;
        vr_req.vifr_mtu=1500;
        vr_req.vifr_mac="\x00\x12\x13\x14\x15\x16";
        ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
                        (nl_get_buf_ptr(cl) + attr_len),
                        (nl_get_buf_len(cl) - attr_len), &error);

        if ((ret <= 0) || error) {
                return ret;
        }
        ret=send_recive_check(ret);
        memset(str,0,MAX_STR);
        strncpy(str,"AGENT interface addition ",MAX_STR-1);
        test_print(str,0,0);
        cleanup();

        /*
         *
         * vifr_os_idx is 0
         *
         */
        system("ip tuntap add dev taptest mode tap");
        sleep(1);
        setup_nl();
        memset(&vr_req,0,sizeof(vr_req));
        vr_req.h_op=SANDESH_OP_ADD;
        vr_req.vifr_type=VIF_TYPE_AGENT;
        vr_req.vifr_idx= VR_MAX_INTERFACES-2 ;
        vr_req.vifr_mac_size=6;
        vr_req.vifr_mtu=1500;
        vr_req.vifr_mac="\x00\x12\x13\x14\x15\x16";
        ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
                        (nl_get_buf_ptr(cl) + attr_len),
                        (nl_get_buf_len(cl) - attr_len), &error);

        if ((ret <= 0) || error) {
                return ret;
        }
        ret=send_recive_check(ret);
        memset(str,0,MAX_STR);
        strncpy(str,"vifr_os_idx is 0 ",MAX_STR-1);
        test_print(str, -EINVAL,offsetof(vr_interface_req,vifr_os_idx));
        cleanup();
}
int 
get_vif_interface()
{
    vr_interface_req vr_req;
    int ret=0,attr_len,error=0;
    char *str=(char *) malloc(MAX_STR);

    if(!str) {
        printf("Memmory allocation has failed\n");
        exit(1);
    }

    attr_len = nl_get_attr_hdr_size();
    /*
     *
     *creating  a tap interface and attaching it to the vrouter with all fields are proper
     *
     */
    setup_nl();
    system("ip tuntap add dev taptest mode tap");
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
    /*
     *
     *GET opertion with proper vifr_idx field
     *
     */         

    setup_nl();
    memset(&vr_req,0,sizeof(vr_req));
    vr_req.h_op=SANDESH_OP_GET;
    vr_req.vifr_idx= VR_MAX_INTERFACES-2;
    ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"GET operation on existed device ",MAX_STR-1);
    test_print(str, 0,0);

    /*
     *
     *GET opertion without  proper vifr_idx field and with proper vifr_os_idx
     *
     */

    setup_nl();
    memset(&vr_req,0,sizeof(vr_req));
    vr_req.h_op=SANDESH_OP_GET;
    vr_req.vifr_idx= VR_MAX_INTERFACES+2;
    vr_req.vifr_os_idx=if_nametoindex("taptest");
    ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"GET operation on non existed device on vrouter ",MAX_STR-1);
    test_print(str, 0,0);

    /*
     *
     *GET opertion without  proper vifr_idx , vifr_os_idx feilds
     *
     */

    setup_nl();
    memset(&vr_req,0,sizeof(vr_req));
    vr_req.h_op=SANDESH_OP_GET;
    vr_req.vifr_idx= VR_MAX_INTERFACES+2;
    ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"GET operation on non existed device on vrouter ",MAX_STR-1);
    test_print(str, -ENOENT,offsetof(vr_interface_req,vifr_idx));
    cleanup();
}
int delete_vif_interface()
{
    vr_interface_req vr_req;
    int ret=0,attr_len,error=0;
    char *str=(char *) malloc(MAX_STR);

    if(!str)
    {
        printf("Memmory allocation has failed\n");
        exit(1);
    }
    attr_len = nl_get_attr_hdr_size();
    /*
     *
     *creating  a tap interface and attaching it to the vrouter with all fields are proper
     *
     */
    setup_nl();
    system("ip tuntap add dev taptest mode tap");
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

    /*
     *     
     * DELETE operation 
     *
     */
    setup_nl();
    memset(&vr_req,0,sizeof(vr_req));
    vr_req.h_op=SANDESH_OP_DELETE;
    vr_req.vifr_idx= VR_MAX_INTERFACES-2 ;
    ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"DELETE operation on  existed device  ",MAX_STR-1);
    test_print(str, 0,0);
    /*
     *     
     *DELETE operation on non-existed device         
     *             
     */
    setup_nl();
    memset(&vr_req,0,sizeof(vr_req));
    vr_req.h_op=SANDESH_OP_DELETE;
    vr_req.vifr_idx= VR_MAX_INTERFACES+2 ;
    ret = sandesh_encode(&vr_req, "vr_interface_req", vr_find_sandesh_info,
            (nl_get_buf_ptr(cl) + attr_len),
            (nl_get_buf_len(cl) - attr_len), &error);
    if ((ret <= 0) || error) {
        return ret;
    }
    ret=send_recive_check(ret);
    memset(str,0,MAX_STR);
    strncpy(str,"DELETE operation on  non-existed device  ",MAX_STR-1);
    test_print(str, -ENODEV,offsetof(vr_interface_req,vifr_idx));

    cleanup();
}
int interface_testcases()
{

    int ret;
    int opt;
    int ind;

    soft_reset();
    setup_environment(0);
    printf("-------------Interface ADD/UPDATE testcases---------\n");
    add_interface_to_vif();
    printf("-------------Interface GET testcases--------------\n");
    get_vif_interface();
    printf("-------------Interface DELETION testcase----------\n");
    delete_vif_interface();
    cleanup();
    return 0;
}
