#include"vr_tests.h"

static int print_message=1;

void
create_flow_req(unsigned int op,unsigned int flow_index,unsgined int src_ip,unsigned int dst_ip,
		uint16_t key_proto,uint16_t src_port,uint16_t dst_port,uint16_t vrf_id,char action,unsigned int mirror)
{
	vr_flow_req flow_req;
	int ret=0, error=0;
	struct nl_response *resp;

	flow_req.fr_op = op;
	flow_req.fr_index = flow_index;
	flow_req.fr_flags = VR_FLOW_FLAG_ACTIVE;
	flow_req.fr_flow_sip = src_ip;
	flow_req.fr_flow_dip = dst_ip;
	flow_req.fr_flow_proto = key_proto;
	flow_req.fr_flow_sport = src_port;
	flow_req.fr_flow_dport = dst_port;
	flow_req.fr_flow_vrf = vrf_id;


	switch (action) {
		case 'd':
			flow_req.fr_action = VR_FLOW_ACTION_DROP;
			break;

		case 'f':
			flow_req.fr_action = VR_FLOW_ACTION_FORWARD;
			break;

		case 'i':
			flow_req.fr_flags = VR_FLOW_FLAG_ACTIVE ^ VR_FLOW_FLAG_ACTIVE;
			flow_req.fr_action = VR_FLOW_ACTION_DROP;
			break;

		default:
			return;
	}

	if (mirror >= 0) {
		flow_req.fr_mir_id = mirror;
		flow_req.fr_flags |= VR_FLOW_FLAG_MIRROR;
	} else
		flow_req.fr_flags &= ~VR_FLOW_FLAG_MIRROR;

	setup_nl();
	ret = sandesh_encode(&flow_req, "vr_flow_req", vr_find_sandesh_info,
			(nl_get_buf_ptr(cl) + attr_len),
			(nl_get_buf_len(cl) - attr_len), &error);
	if ((ret <= 0) || error) {
		return ret;
	}
	ret=send_recive_check(ret);
	if(print_message)
		test_print(str,expected_ret,offset);
}

void setup_flow_environment()
{
	char str[MAX_STR];
	/*creates a inetrface,attaches to vif and then creates a nexthop*/
	setup_mirror_environment();
	
	/*creating a mirror */
	memset(str,0,sizeof(str));
	print_message=1;
	strncpy(str,"mirror ADD test case with proper mirror index and nhid",MAX_STR-1);
	/*1:op 2:nhid 3:mirror index 4:str to be printed 5:expected return value 6:expected offset*/
	create_mirror_req(SANDESH_OP_ADD,NH_TABLE_ENTRIES-2,VR_MAX_MIRROR_INDICES-2,str,0,0);
}
void create_flow_test_cases()
{
	/*1:op 2:flow_index 3:src_ip 4:dst_ip 5:proto 6:src_port 7:dst_port 8:vrf 9:action 10:mirror index*/

}
void flow_test_case()
{
	setup_flow_environment();
	
	create_flow_test_cases();
}
