/*
 * vr_stats.c -- catch all stats support. basically for stats which don't
 * go well in any other bucket, for eg: packet drop statistics
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_types.h>
#include <vr_packet.h>
#include "vr_message.h"
#include <linux/kernel.h>
#include "vr_stats.h"

void vr_stats_exit(struct vrouter *, bool);
int vr_stats_init(struct vrouter *);
static void
vr_drop_stats_fill_response(vr_drop_stats_req *response,
		struct vr_drop_stats *stats)
{
	response->vds_discard = stats->vds_discard;
	response->vds_pull = stats->vds_pull;
	response->vds_invalid_if = stats->vds_invalid_if;
	response->vds_arp_no_where_to_go = stats->vds_arp_no_where_to_go;
	response->vds_garp_from_vm = stats->vds_garp_from_vm;
	response->vds_invalid_arp = stats->vds_invalid_arp;
	response->vds_trap_no_if = stats->vds_trap_no_if;
	response->vds_nowhere_to_go = stats->vds_nowhere_to_go;
	response->vds_flow_queue_limit_exceeded =
			stats->vds_flow_queue_limit_exceeded;
	response->vds_flow_no_memory = stats->vds_flow_no_memory;
	response->vds_flow_invalid_protocol =
			stats->vds_flow_invalid_protocol;
	response->vds_flow_nat_no_rflow = stats->vds_flow_nat_no_rflow;
	response->vds_flow_action_drop = stats->vds_flow_action_drop;
	response->vds_flow_action_invalid = stats->vds_flow_action_invalid;
	response->vds_flow_unusable = stats->vds_flow_unusable;
	response->vds_flow_table_full = stats->vds_flow_table_full;
	response->vds_interface_tx_discard = stats->vds_interface_tx_discard;
	response->vds_interface_drop = stats->vds_interface_drop;
	response->vds_duplicated = stats->vds_duplicated;
	response->vds_push = stats->vds_push;
	response->vds_ttl_exceeded = stats->vds_ttl_exceeded;
	response->vds_invalid_nh = stats->vds_invalid_nh;
	response->vds_invalid_label = stats->vds_invalid_label;
	response->vds_invalid_protocol = stats->vds_invalid_protocol;
	response->vds_interface_rx_discard = stats->vds_interface_rx_discard;
	response->vds_invalid_mcast_source = stats->vds_invalid_mcast_source;
	response->vds_head_alloc_fail = stats->vds_head_alloc_fail;
	response->vds_head_space_reserve_fail = stats->vds_head_space_reserve_fail;
	response->vds_pcow_fail = stats->vds_pcow_fail;
	response->vds_mcast_df_bit = stats->vds_mcast_df_bit;
	response->vds_mcast_clone_fail = stats->vds_mcast_clone_fail;
	response->vds_composite_invalid_interface =
			stats->vds_composite_invalid_interface;
	response->vds_rewrite_fail = stats->vds_rewrite_fail;
	response->vds_misc = stats->vds_misc;
	response->vds_invalid_packet = stats->vds_invalid_packet;
	response->vds_cksum_err = stats->vds_cksum_err;
	response->vds_clone_fail = stats->vds_clone_fail;
	response->vds_no_fmd = stats->vds_no_fmd;
	response->vds_cloned_original =
			stats->vds_cloned_original;
	response->vds_invalid_vnid = stats->vds_invalid_vnid;
	response->vds_frag_err = stats->vds_frag_err;
	response->vds_invalid_source = stats->vds_invalid_source;
	response->vds_arp_no_route = stats->vds_arp_no_route;
	response->vds_l2_no_route = stats->vds_l2_no_route;
	response->vds_arp_reply_no_route = stats->vds_arp_reply_no_route;

	return;
}

static void
vr_drop_stats_get(short is_filtered)
{
	int ret = 0;
	unsigned int cpu;
	struct vrouter *router = vrouter_get(0);
	vr_drop_stats_req *response = NULL;
	struct vr_drop_stats *stats_block, *stats = NULL;
	uint64_t **temp=NULL;

	if (!router && (ret = -ENOENT))
		goto exit_get;

	stats = vr_zalloc(sizeof(*stats));
	if (!stats && (ret = -ENOMEM))
		goto exit_get;

	response = vr_zalloc(sizeof(*response));
	if (!response && (ret = -ENOMEM))
		goto exit_get;

	if(is_filtered){
		if(router->vr_drop_stats_filter)
			temp = router->vr_pdrop_stats_filter;
		else{
			ret = -NO_FILTER_REGISTERED;
			goto exit_get;
		}
	}
	else
		temp = router->vr_pdrop_stats;

	for (cpu = 0; cpu < vr_num_cpus; cpu++) {

		stats_block = (struct vr_drop_stats *)temp[cpu];
		stats->vds_discard += stats_block->vds_discard;
		stats->vds_pull += stats_block->vds_pull;
		stats->vds_invalid_if += stats_block->vds_invalid_if;
		stats->vds_arp_no_where_to_go +=
				stats_block->vds_arp_no_where_to_go;
		stats->vds_garp_from_vm += stats_block->vds_garp_from_vm;
		stats->vds_invalid_arp += stats_block->vds_invalid_arp;
		stats->vds_trap_no_if += stats_block->vds_trap_no_if;
		stats->vds_nowhere_to_go += stats_block->vds_nowhere_to_go;
		stats->vds_flow_queue_limit_exceeded +=
				stats_block->vds_flow_queue_limit_exceeded;
		stats->vds_flow_no_memory += stats_block->vds_flow_no_memory;
		stats->vds_flow_invalid_protocol +=
				stats_block->vds_flow_invalid_protocol;
		stats->vds_flow_nat_no_rflow += stats_block->vds_flow_nat_no_rflow;
		stats->vds_flow_action_drop += stats_block->vds_flow_action_drop;
		stats->vds_flow_action_invalid += stats_block->vds_flow_action_invalid;
		stats->vds_flow_unusable += stats_block->vds_flow_unusable;
		stats->vds_flow_table_full += stats_block->vds_flow_table_full;
		stats->vds_interface_tx_discard += stats_block->vds_interface_tx_discard;
		stats->vds_interface_drop += stats_block->vds_interface_drop;
		stats->vds_duplicated += stats_block->vds_duplicated;
		stats->vds_push += stats_block->vds_push;
		stats->vds_ttl_exceeded += stats_block->vds_ttl_exceeded;
		stats->vds_invalid_nh += stats_block->vds_invalid_nh;
		stats->vds_invalid_label += stats_block->vds_invalid_label;
		stats->vds_invalid_protocol += stats_block->vds_invalid_protocol;
		stats->vds_interface_rx_discard += stats_block->vds_interface_rx_discard;
		stats->vds_invalid_mcast_source += stats_block->vds_invalid_mcast_source;
		stats->vds_head_alloc_fail += stats_block->vds_head_alloc_fail;
		stats->vds_head_space_reserve_fail += stats_block->vds_head_space_reserve_fail;
		stats->vds_pcow_fail += stats_block->vds_pcow_fail;
		stats->vds_mcast_df_bit += stats_block->vds_mcast_df_bit;
		stats->vds_mcast_clone_fail += stats_block->vds_mcast_clone_fail;
		stats->vds_composite_invalid_interface +=
				stats_block->vds_composite_invalid_interface;
		stats->vds_rewrite_fail += stats_block->vds_rewrite_fail;
		stats->vds_misc += stats_block->vds_misc;
		stats->vds_invalid_packet += stats_block->vds_invalid_packet;
		stats->vds_cksum_err += stats_block->vds_cksum_err;
		stats->vds_clone_fail += stats_block->vds_clone_fail;
		stats->vds_no_fmd += stats_block->vds_no_fmd;
		stats->vds_cloned_original += stats_block->vds_cloned_original;
		stats->vds_invalid_vnid += stats_block->vds_invalid_vnid;
		stats->vds_frag_err += stats_block->vds_frag_err;
		stats->vds_invalid_source += stats_block->vds_invalid_source;
		stats->vds_arp_no_route += stats_block->vds_arp_no_route;
		stats->vds_l2_no_route += stats_block->vds_l2_no_route;
		stats->vds_arp_reply_no_route +=
				stats_block->vds_arp_reply_no_route;
	}


	vr_drop_stats_fill_response(response, stats);

	exit_get:
	vr_message_response(VR_DROP_STATS_OBJECT_ID, ret ? NULL : response, ret);
	if (stats != NULL)
		vr_free(stats);

	if (response != NULL)
		vr_free(response);

	return;
}

void
vr_drop_stats_req_process(void *s_req)
{
	int ret;
	vr_drop_stats_req *req = (vr_drop_stats_req *)s_req;

	if ((req->h_op != SANDESH_OP_GET) && (ret = -EOPNOTSUPP))
		vr_send_response(ret);

	vr_drop_stats_get(req->vds_is_filtered);
	return;
}
static void vr_clean_up_stats(uint64_t **free_ptr){
	unsigned int i;
	for (i = 0; i < vr_num_cpus; i++) {
		if (!free_ptr[i])
			break;
		vr_free(free_ptr[i]);
		free_ptr[i] = NULL;
	}
	vr_free(free_ptr);
}
static void
vr_pkt_drop_stats_exit(struct vrouter *router,short clean_all)
{
	if(clean_all && router->vr_pdrop_stats) {
		vr_clean_up_stats(router->vr_pdrop_stats);
		router->vr_pdrop_stats=NULL;
	}
	if(router->vr_drop_stats_filter) {
		vr_clean_up_stats(router->vr_pdrop_stats_filter);
		router->vr_pdrop_stats_filter=NULL;
		vr_free(router->vr_drop_stats_filter);
		router->vr_drop_stats_filter = NULL;
	}
	return;
}

static int
vr_pkt_drop_stats_init(struct vrouter *router)
{
	unsigned int i = 0;
	unsigned int size = 0;
	short clean_all=1;
	uint64_t ** temp;
	size = sizeof(void *) * vr_num_cpus;
	if(router->vr_drop_stats_filter){
		if (router->vr_pdrop_stats_filter)
			return 0;
		router->vr_pdrop_stats_filter = vr_zalloc(size);
		temp = router->vr_pdrop_stats_filter;
		clean_all=0;
	}
	else{
		if (router->vr_pdrop_stats)
			return 0;
		router->vr_pdrop_stats = vr_zalloc(size);
		temp = router->vr_pdrop_stats;
	}
	if (!temp) {
		vr_printf("Failed to initialize the stats\n");
		vr_module_error(-ENOMEM, __FUNCTION__,
				__LINE__, size);
		goto cleanup;
	}

	size = VP_DROP_MAX * sizeof(uint64_t);
	for (i = 0; i < vr_num_cpus; i++) {
		temp[i] = vr_zalloc(size);
		if (!temp[i]) {
			vr_printf("Failed to initialize the stats\n");
			vr_module_error(-ENOMEM, __FUNCTION__,
					__LINE__, i);
			goto cleanup;
		}
	}

	return 0;

	cleanup:
	vr_pkt_drop_stats_exit(router,clean_all);
	return -ENOMEM;
}

static void
vr_pkt_drop_stats_reset(struct vrouter *router)
{
	unsigned int i;
	if (router->vr_pdrop_stats) {
		for (i = 0; i < vr_num_cpus; i++) {
			if (router->vr_pdrop_stats[i])
				memset(router->vr_pdrop_stats[i], 0, VP_DROP_MAX * sizeof(uint64_t));
		}
	}
	if (router->vr_pdrop_stats_filter) {
		for (i = 0; i < vr_num_cpus; i++) {
			if (router->vr_pdrop_stats_filter[i])
				memset(router->vr_pdrop_stats[i], 0, VP_DROP_MAX * sizeof(uint64_t));
		}
	}
	return;
}

void
vr_stats_exit(struct vrouter *router, bool soft_reset)
{
	short clean_all=1;
	if (soft_reset) {
		vr_pkt_drop_stats_reset(router);
		return;
	}
	vr_pkt_drop_stats_exit(router,clean_all);
	return;
}

int
vr_stats_init(struct vrouter *router)
{
	return vr_pkt_drop_stats_init(router);
}
void print_filter( vr_drop_stats_register *request) {
	vr_printf("Printing filter \n");
	if(request->__isset_destination_ip)
		vr_printf("Destination ip %d\n",request->destination_ip);
	if(request->__isset_destination_port)
		vr_printf("Destination port %d\n",request->destination_port);
	if(request->source_ip)
		vr_printf("Source ip %d\n",request->source_ip);
	if(request->__isset_source_port)
		vr_printf("source port %d \n",request->source_port);
	if(request->__isset_protocol)
		vr_printf("protocol %d \n",request->protocol);
	if(request->__isset_vrf)
		vr_printf("vrf %d \n", request->vrf);
}
void print_tuple(struct vr_registered_tuple *input) {
	vr_printf("Printing tuple \n");
	vr_printf("Destination ip %d\n",input->dst_ip);
	vr_printf("Destination port %d\n",input->dst_port);
	vr_printf("Source ip %d\n",input->src_ip);
	vr_printf("source port %d \n",input->src_port);
	vr_printf("protocol %d \n",input->protocol);
	vr_printf("vrf is %d \n",input->vrf);
}

void vr_drop_stats_register_process(void *register_req )
{
	vr_response response;
	vr_drop_stats_register *request = (vr_drop_stats_register *)register_req;
	short clean_all=0;
	struct vrouter *router = vrouter_get(0);
	response.h_op = SANDESH_OP_RESPONSE;
	if(request->h_op==SANDESH_OP_ADD) {

		if(!router)
		{
			vr_send_response(-EINVAL);
			return;
		}
		router->vr_drop_stats_filter = vr_zalloc(sizeof(vr_drop_stats_register));
		if(!router->vr_drop_stats_filter) {
			vr_send_response(-EINVAL);
			return;
		}
		memcpy(router->vr_drop_stats_filter, request,sizeof(vr_drop_stats_register));
		if(vr_pkt_drop_stats_init(router) < 0)
		{
			vr_free(router->vr_drop_stats_filter);
			vr_send_response(-EINVAL);
			return;
		}
		response.resp_code=1;
		goto send_response;
	}
	else if(request->h_op == SANDESH_OP_DELETE)
	{
		if(router->vr_drop_stats_filter){
			vr_pkt_drop_stats_exit(router,clean_all);
			response.resp_code=1;
		}
		else
			response.resp_code=NO_FILTER_REGISTERED;
		goto send_response;
	}
	else if(request->h_op == SANDESH_OP_GET) {
		vr_drop_stats_register *filter_response ;
		if((filter_response = router->vr_drop_stats_filter)!=NULL)
			vr_message_response(VR_DROP_STATS_REGISTER_OBJ_ID,filter_response,0);
		else
		{
			response.resp_code=-NO_FILTER_REGISTERED;
			goto send_response;
		}
	}
	else{
		vr_send_response(-EOPNOTSUPP);
		return;
	}
	send_response:
	vr_message_response(VR_RESPONSE_OBJECT_ID, &response, 0);
}

static int
is_matched_with_filter(struct vr_registered_tuple *input)
{
	struct vrouter *router = NULL;
	if(!input)
		return 0;

	router = (struct vrouter *)vrouter_get(0);
	if(router->vr_drop_stats_filter->protocol)
		if(router->vr_drop_stats_filter->protocol !=input->protocol)
			return 0;
	if(router->vr_drop_stats_filter->destination_ip)
		if(router->vr_drop_stats_filter->destination_ip != input->dst_ip)
			return 0;
	if(router->vr_drop_stats_filter->source_ip)
		if(router->vr_drop_stats_filter->source_ip != input->src_ip)
			return 0;
	if(router->vr_drop_stats_filter->source_port)
		if(router->vr_drop_stats_filter->source_port != input->src_port)
			return 0;
	if(router->vr_drop_stats_filter->destination_port)
		if(router->vr_drop_stats_filter->destination_port != input->dst_port)
			return 0;
	if(router->vr_drop_stats_filter->vrf)
		if(router->vr_drop_stats_filter->vrf != input->vrf)
			return 0;
	return 1;
}
static int
vr_make_tuple_from_pkt(struct vr_packet *pkt, short vrf,
		struct vr_registered_tuple *tuple)
{
	int hlen=0;
	struct vr_ip *iph = NULL;

	iph = (struct vr_ip *)vr_network_header(pkt);
	if(!iph)
		return -1;
	tuple->vrf =vrf;
	tuple->dst_ip = iph->ip_daddr;
	tuple->src_ip = iph->ip_saddr;
	tuple->protocol = iph->ip_proto;
	hlen = iph->ip_hl*4;
	tuple->src_port = 0;
	tuple->dst_port = 0;
	if(iph->ip_proto == VR_IP_PROTO_TCP) {
		struct vr_tcp *tcphdr = (struct vr_tcp *)((char *)iph + hlen);
		if(tcphdr) {
			tuple->src_port = ntohs(tcphdr->tcp_sport);
			tuple->dst_port = ntohs(tcphdr->tcp_dport);
		}
	}
	else if(iph->ip_proto == VR_IP_PROTO_UDP) {
		struct vr_udp *udphdr = (struct vr_udp *)((char *)iph + hlen);
		if(udphdr) {
			tuple->src_port = ntohs(udphdr->udp_sport);
			tuple->dst_port = ntohs(udphdr->udp_dport);
		}
	}
	return 1;
}

void
set_pkt_filter(struct vrouter *router, struct vr_packet *pkt, short vrf){

	if(router->vr_drop_stats_filter) {
		struct vr_registered_tuple tuple;
		if(vr_make_tuple_from_pkt(pkt,vrf, &tuple)) {
			if(is_matched_with_filter(&tuple))
				pkt->is_matched_filter=1;
			else
				pkt->is_matched_filter=0;
		}
	}
	else
		pkt->is_matched_filter=0;
}
