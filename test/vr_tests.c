#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <stdbool.h>
#include <getopt.h>

#include <asm/types.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_ether.h>

#include <net/if.h>
#include <netinet/ether.h>
#include "vr_interface.h"

#include "vr_types.h"
#include "vr_message.h"
#include "vr_nexthop.h"
#include "vr_genetlink.h"
#include "nl_util.h"
#include "vr_tests.h"
#include <signal.h>

char test_case_name[TESTCASE_MAX][MAX_STR]={"Interface",
    "Nexthop",
    "Route",
    "Vxlan",
    "Mpls",
    "Mirror",
    "Flow"};


#define ALL_TESTCASES TESTCASE_MAX
int debug=0;
int testcase;
struct nl_client *cl;
int resp_code=0;
int total_pass[TOTAL_TESTCASES]={0};
int total_fail[TOTAL_TESTCASES]={0};
int offset=0;
int attr_len=0;

void sigint_handler(int signo)
{
    printf("Signal received: %d\n",signo);
    cleanup();
    exit(1);
}
void
vr_response_process(void *s)
{

    vr_response *resp = (vr_response *)s;
    resp_code=resp->resp_code;
    if(resp_code<0)
        offset=resp->offset;
    else
        offset=0;
}

void setup_nl()
{
    int ret=0;
    ret = nl_build_nlh(cl, cl->cl_genl_family_id, NLM_F_REQUEST);
    if (ret) {
        exit(1);
    }
    /* Generic nlmsg header */
    ret = nl_build_genlh(cl, SANDESH_REQUEST, 0);
    if (ret) {
        exit(1);
    }
}

int 
soft_reset()
{
    int error;
    int ret=0;

    setup_nl();
    vrouter_ops vops;
    vops.h_op=SANDESH_OP_RESET;
    error = 0;
    ret = sandesh_encode(&vops, "vrouter_ops", vr_find_sandesh_info,
                        (nl_get_buf_ptr(cl) + attr_len),
                        (nl_get_buf_len(cl) - attr_len), &error);

    if ((ret <= 0) || error) {
        return  ret; 
    }
    send_recive_check(ret);
}


int  send_recive_check(int ret)
{
    struct nl_response *resp;
    int error=0;

    nl_build_attr(cl, ret, NL_ATTR_VR_MESSAGE_PROTOCOL);
    nl_update_nlh(cl);

        /* Send the request to kernel */
    ret = nl_sendmsg(cl);
    while ((ret = nl_recvmsg(cl)) > 0) {
        resp = nl_parse_reply(cl);
        if (resp->nl_op == SANDESH_REQUEST) {
            sandesh_decode(resp->nl_data, resp->nl_len, vr_find_sandesh_info, &error);
        }
    }
    return 0;
}
void test_print(char *str, int expected_value,int off)
{
    if(resp_code==expected_value) {
        printf("return value:%3d,expected:%3d\t%s testcase has passed",resp_code,expected_value,str);
        if(expected_value<0 && off==offset)
            printf(" as expected but the value at Offset %3d is wrong\n",offset);
        else
            printf("\n");
        total_pass[testcase]++;
    }
    else {
        if(resp_code==-ENODEV || resp_code==-ENOMEM ) {
            printf("return value:%3d,expected:%3d\t%s Testcase has failed\n",resp_code,expected_value,str);
        }
        else
            printf("Error: return value:%3d,expected:%3d\t%s testcase failed and offset is :%3d\n",resp_code,expected_value,str,offset);
        total_fail[testcase]++;
    }
    if(debug||resp_code!=expected_value) {
        if(testcase==INTERFACE)
            system("vif --list >> /var/tmp/test_cases.txt;echo >>  /var/tmp/test_cases.txt");
        else if(testcase == NEXTHOP)
            system("echo \"NEXT HOP testcases\" >> /var/tmp/test_cases.txt;nh --list >> /var/tmp/test_cases.txt;echo >>  /var/tmp/test_cases.txt");
        else if(testcase == ROUTE)
            system("echo \"ROUTE testcases\" >> /var/tmp/test_cases.txt;rt --dump 0 >> /var/tmp/test_cases.txt;echo >>  /var/tmp/test_cases.txt");
        else if(testcase == VXLAN)
            system("echo \"Vxlan testcases\" >>/var/tmp/test_cases.txt ;/var/tmp/vxlan -b >>/var/tmp/test_cases.txt;echo >>  /var/tmp/test_cases.txt");
    }
}
void
setup_environment(int print)
{
    system("ip tuntap add dev taptest mode tap");
    sleep(1);
    soft_reset();
    add_interface(print);
}
void
cleanup()
{
    soft_reset();
    system("ip tuntap del dev taptest mode tap");
}
void 
usage()
{
    int i=0;
    printf("\n<executable>\t\t-c <count> to repeat the tests\n \
            -d to enable debug and collect the outputs to file\n \
            -h help \n \
            -a all test cases\n \
            -t <value> ");
    for(i;i<TESTCASE_MAX-1;i++)
        printf("%d:%s ",i+1,test_case_name[i]);
    printf("\n");
    exit(1);
}
void 
run_interface_related_testcases()
{
    printf("*********************************\n");
    printf("Runnig interface related test cases\n");
    printf("*********************************\n");
    testcase=INTERFACE;
    interface_testcases();
    printf("\n\n");
}
void 
run_nexthop_related_testcases()
{
    printf("*********************************\n");
    printf("Runnig nexthop related test cases\n");
    printf("*********************************\n");
    testcase=NEXTHOP;
    nexthop_testcases();
    printf("\n\n");
}

void run_route_related_testcases()
{
    printf("*********************************\n");
    printf("Running route related testcases\n");
    printf("*********************************\n");
    testcase=ROUTE;
    vr_route_testcases();
    printf("\n\n");
}
void run_vxlan_related_testcases()
{
    printf("*********************************\n");
    printf("Running vxlan related test cases\n");
    printf("*********************************\n");
    testcase=VXLAN;
    vxlan_test_cases();
    printf("\n\n");
}
void run_mpls_related_testcases()
{
    printf("*********************************\n");
    printf("Running mpls related test cases\n");
    printf("*********************************\n");
    testcase=MPLS;
    mpls_test_cases();
    printf("\n\n");
}
void run_mirror_related_testcases()
{
    printf("*********************************\n");
    printf("Running mirror related test cases\n");
    printf("*********************************\n");
    testcase=MIRROR;
    mirror_test_cases();
    printf("\n\n");
}

int main(int argc,char *argv[])
{
    int i=0;
    int count=1;
    int opt=0;
    int ret=0;
    int test=0;
    while((opt=getopt(argc, argv, "c:dt:ha")) != -1) {
        switch(opt) {
            case 'c': 
                count=atoi(optarg);
                break;
            case 'd':
                /*Removing old debug file*/
                unlink("/var/tmp/test_cases.txt");
                debug=1;
                break;
            case 't':
                if(test==0)
                    test=atoi(optarg);
                break;
            case 'a':
                if(test==0)
                    test=ALL_TESTCASES; 
                break;
            case 'h':
            default:
                usage();
                break;
        }
    }

    sleep(1);

    signal(SIGINT,sigint_handler);
    cl = nl_register_client();
    if (!cl) {
        exit(1);
    }

    ret = nl_socket(cl, NETLINK_GENERIC);
    if (ret <= 0) {
        exit(1);
    }

    if (vrouter_get_family_id(cl) <= 0) {
        return 0;
    }

    attr_len = nl_get_attr_hdr_size();
    while(count-- >0 ) {
        switch(test)
        {
            case 1: 
                run_interface_related_testcases();
                break;
            case 2:
                run_nexthop_related_testcases();
                break;
            case 3:
                run_route_related_testcases();
                break;
            case 4:
                run_vxlan_related_testcases();
                break;
            case 5:
                run_mpls_related_testcases();
                break;
            case 6:
                run_mirror_related_testcases();
                break;
            default:
                usage();
                break;
            case ALL_TESTCASES:
                printf("*************************\n");
                printf("Running all the testcases\n");
                printf("*************************\n\n\n");
                run_interface_related_testcases();
                run_nexthop_related_testcases();
                run_route_related_testcases();
                run_vxlan_related_testcases();
                run_mpls_related_testcases();
                run_mirror_related_testcases();
                break;
        }
        printf("************final results************\n");

        for(i=0;i<TESTCASE_MAX;i++) {
            if(total_pass[i]+total_fail[i])
                printf("%10s Testcases: Total test cases: %2d  Passed:%2d Failed:%2d\n",test_case_name[i],total_pass[i]+total_fail[i], total_pass[i],total_fail[i]);
        }
    }
    return 0;
}
