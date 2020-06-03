vr_mem_stats_table = {}

vr_mem_stats_table[1] = {}
vr_mem_stats_table[1].field_name = "vr_mem_stats_h_op"
vr_mem_stats_table[1].ProtoField = ProtoField.int8
vr_mem_stats_table[1].base = base.DEC
vr_mem_stats_table[1].append_value = {
               branch = {
                           prepend = ": ",
                           value = function (val) return sandesh_op[val] end
                        },
               subtree = {
                           prepend = ", Operation: ",
                           value = function (val) return sandesh_op[val] end
                         }}
vr_mem_stats_table[1].info_col = {prepend = "Operation: "}
vr_mem_stats_table[1].show_when_zero = true

vr_mem_stats_table[2] = {}
vr_mem_stats_table[2].field_name = "vms_rid"
vr_mem_stats_table[2].ProtoField = ProtoField.int16
vr_mem_stats_table[2].base = base.DEC

vr_mem_stats_table[3] = {}
vr_mem_stats_table[3].field_name = "vms_alloced"
vr_mem_stats_table[3].ProtoField = ProtoField.int64
vr_mem_stats_table[3].base = base.DEC

vr_mem_stats_table[4] = {}
vr_mem_stats_table[4].field_name = "vms_freed"
vr_mem_stats_table[4].ProtoField = ProtoField.int64
vr_mem_stats_table[4].base = base.DEC

vr_mem_stats_table[5] = {}
vr_mem_stats_table[5].field_name = "vms_assembler_table_object"
vr_mem_stats_table[5].ProtoField = ProtoField.int64
vr_mem_stats_table[5].base = base.DEC

vr_mem_stats_table[6] = {}
vr_mem_stats_table[6].field_name = "vms_bridge_mac_object"
vr_mem_stats_table[6].ProtoField = ProtoField.int64
vr_mem_stats_table[6].base = base.DEC

vr_mem_stats_table[7] = {}
vr_mem_stats_table[7].field_name = "vms_btable_object"
vr_mem_stats_table[7].ProtoField = ProtoField.int64
vr_mem_stats_table[7].base = base.DEC

vr_mem_stats_table[8] = {}
vr_mem_stats_table[8].field_name = "vms_build_info_object"
vr_mem_stats_table[8].ProtoField = ProtoField.int64
vr_mem_stats_table[8].base = base.DEC

vr_mem_stats_table[9] = {}
vr_mem_stats_table[9].field_name = "vms_defer_object"
vr_mem_stats_table[9].ProtoField = ProtoField.int64
vr_mem_stats_table[9].base = base.DEC

vr_mem_stats_table[10] = {}
vr_mem_stats_table[10].field_name = "vms_drop_stats_object"
vr_mem_stats_table[10].ProtoField = ProtoField.int64
vr_mem_stats_table[10].base = base.DEC

vr_mem_stats_table[11] = {}
vr_mem_stats_table[11].field_name = "vms_drop_stats_req_object"
vr_mem_stats_table[11].ProtoField = ProtoField.int64
vr_mem_stats_table[11].base = base.DEC

vr_mem_stats_table[12] = {}
vr_mem_stats_table[12].field_name = "vms_flow_queue_object"
vr_mem_stats_table[12].ProtoField = ProtoField.int64
vr_mem_stats_table[12].base = base.DEC

vr_mem_stats_table[13] = {}
vr_mem_stats_table[13].field_name = "vms_flow_req_object"
vr_mem_stats_table[13].ProtoField = ProtoField.int64
vr_mem_stats_table[13].base = base.DEC

vr_mem_stats_table[14] = {}
vr_mem_stats_table[14].field_name = "vms_flow_req_path_object"
vr_mem_stats_table[14].ProtoField = ProtoField.int64
vr_mem_stats_table[14].base = base.DEC

vr_mem_stats_table[15] = {}
vr_mem_stats_table[15].field_name = "vms_flow_hold_stat_object"
vr_mem_stats_table[15].ProtoField = ProtoField.int64
vr_mem_stats_table[15].base = base.DEC

vr_mem_stats_table[16] = {}
vr_mem_stats_table[16].field_name = "vms_flow_link_local_object"
vr_mem_stats_table[16].ProtoField = ProtoField.int64
vr_mem_stats_table[16].base = base.DEC

vr_mem_stats_table[17] = {}
vr_mem_stats_table[17].field_name = "vms_flow_metadata_object"
vr_mem_stats_table[17].ProtoField = ProtoField.int64
vr_mem_stats_table[17].base = base.DEC

vr_mem_stats_table[18] = {}
vr_mem_stats_table[18].field_name = "vms_flow_table_data_object"
vr_mem_stats_table[18].ProtoField = ProtoField.int64
vr_mem_stats_table[18].base = base.DEC

vr_mem_stats_table[19] = {}
vr_mem_stats_table[19].field_name = "vms_flow_table_info_object"
vr_mem_stats_table[19].ProtoField = ProtoField.int64
vr_mem_stats_table[19].base = base.DEC

vr_mem_stats_table[20] = {}
vr_mem_stats_table[20].field_name = "vms_fragment_object"
vr_mem_stats_table[20].ProtoField = ProtoField.int64
vr_mem_stats_table[20].base = base.DEC

vr_mem_stats_table[21] = {}
vr_mem_stats_table[21].field_name = "vms_fragment_queue_object"
vr_mem_stats_table[21].ProtoField = ProtoField.int64
vr_mem_stats_table[21].base = base.DEC

vr_mem_stats_table[22] = {}
vr_mem_stats_table[22].field_name = "vms_fragment_queue_element_object"
vr_mem_stats_table[22].ProtoField = ProtoField.int64
vr_mem_stats_table[22].base = base.DEC

vr_mem_stats_table[23] = {}
vr_mem_stats_table[23].field_name = "vms_fragment_scanner_object"
vr_mem_stats_table[23].ProtoField = ProtoField.int64
vr_mem_stats_table[23].base = base.DEC

vr_mem_stats_table[24] = {}
vr_mem_stats_table[24].field_name = "vms_hpacket_pool_object"
vr_mem_stats_table[24].ProtoField = ProtoField.int64
vr_mem_stats_table[24].base = base.DEC

vr_mem_stats_table[25] = {}
vr_mem_stats_table[25].field_name = "vms_htable_object"
vr_mem_stats_table[25].ProtoField = ProtoField.int64
vr_mem_stats_table[25].base = base.DEC

vr_mem_stats_table[26] = {}
vr_mem_stats_table[26].field_name = "vms_interface_object"
vr_mem_stats_table[26].ProtoField = ProtoField.int64
vr_mem_stats_table[26].base = base.DEC

vr_mem_stats_table[27] = {}
vr_mem_stats_table[27].field_name = "vms_interface_mac_object"
vr_mem_stats_table[27].ProtoField = ProtoField.int64
vr_mem_stats_table[27].base = base.DEC

vr_mem_stats_table[28] = {}
vr_mem_stats_table[28].field_name = "vms_interface_req_object"
vr_mem_stats_table[28].ProtoField = ProtoField.int64
vr_mem_stats_table[28].base = base.DEC

vr_mem_stats_table[29] = {}
vr_mem_stats_table[29].field_name = "vms_interface_req_mac_object"
vr_mem_stats_table[29].ProtoField = ProtoField.int64
vr_mem_stats_table[29].base = base.DEC

vr_mem_stats_table[30] = {}
vr_mem_stats_table[30].field_name = "vms_interface_req_name_object"
vr_mem_stats_table[30].ProtoField = ProtoField.int64
vr_mem_stats_table[30].base = base.DEC

vr_mem_stats_table[31] = {}
vr_mem_stats_table[31].field_name = "vms_interface_stats_object"
vr_mem_stats_table[31].ProtoField = ProtoField.int64
vr_mem_stats_table[31].base = base.DEC

vr_mem_stats_table[32] = {}
vr_mem_stats_table[32].field_name = "vms_interface_table_object"
vr_mem_stats_table[32].ProtoField = ProtoField.int64
vr_mem_stats_table[32].base = base.DEC

vr_mem_stats_table[33] = {}
vr_mem_stats_table[33].field_name = "vms_interface_vrf_table_object"
vr_mem_stats_table[33].ProtoField = ProtoField.int64
vr_mem_stats_table[33].base = base.DEC

vr_mem_stats_table[34] = {}
vr_mem_stats_table[34].field_name = "vms_itable_object"
vr_mem_stats_table[34].ProtoField = ProtoField.int64
vr_mem_stats_table[34].base = base.DEC

vr_mem_stats_table[35] = {}
vr_mem_stats_table[35].field_name = "vms_malloc_object"
vr_mem_stats_table[35].ProtoField = ProtoField.int64
vr_mem_stats_table[35].base = base.DEC

vr_mem_stats_table[36] = {}
vr_mem_stats_table[36].field_name = "vms_message_object"
vr_mem_stats_table[36].ProtoField = ProtoField.int64
vr_mem_stats_table[36].base = base.DEC

vr_mem_stats_table[37] = {}
vr_mem_stats_table[37].field_name = "vms_message_response_object"
vr_mem_stats_table[37].ProtoField = ProtoField.int64
vr_mem_stats_table[37].base = base.DEC

vr_mem_stats_table[38] = {}
vr_mem_stats_table[38].field_name = "vms_message_dump_object"
vr_mem_stats_table[38].ProtoField = ProtoField.int64
vr_mem_stats_table[38].base = base.DEC

vr_mem_stats_table[39] = {}
vr_mem_stats_table[39].field_name = "vms_mem_stats_req_object"
vr_mem_stats_table[39].ProtoField = ProtoField.int64
vr_mem_stats_table[39].base = base.DEC

vr_mem_stats_table[40] = {}
vr_mem_stats_table[40].field_name = "vms_mirror_object"
vr_mem_stats_table[40].ProtoField = ProtoField.int64
vr_mem_stats_table[40].base = base.DEC

vr_mem_stats_table[41] = {}
vr_mem_stats_table[41].field_name = "vms_mirror_table_object"
vr_mem_stats_table[41].ProtoField = ProtoField.int64
vr_mem_stats_table[41].base = base.DEC

vr_mem_stats_table[42] = {}
vr_mem_stats_table[42].field_name = "vms_mirror_meta_object"
vr_mem_stats_table[42].ProtoField = ProtoField.int64
vr_mem_stats_table[42].base = base.DEC

vr_mem_stats_table[43] = {}
vr_mem_stats_table[43].field_name = "vms_mtrie_object"
vr_mem_stats_table[43].ProtoField = ProtoField.int64
vr_mem_stats_table[43].base = base.DEC

vr_mem_stats_table[44] = {}
vr_mem_stats_table[44].field_name = "vms_mtrie_bucket_object"
vr_mem_stats_table[44].ProtoField = ProtoField.int64
vr_mem_stats_table[44].base = base.DEC

vr_mem_stats_table[45] = {}
vr_mem_stats_table[45].field_name = "vms_mtrie_stats_object"
vr_mem_stats_table[45].ProtoField = ProtoField.int64
vr_mem_stats_table[45].base = base.DEC

vr_mem_stats_table[46] = {}
vr_mem_stats_table[46].field_name = "vms_mtrie_table_object"
vr_mem_stats_table[46].ProtoField = ProtoField.int64
vr_mem_stats_table[46].base = base.DEC

vr_mem_stats_table[47] = {}
vr_mem_stats_table[47].field_name = "vms_network_address_object"
vr_mem_stats_table[47].ProtoField = ProtoField.int64
vr_mem_stats_table[47].base = base.DEC

vr_mem_stats_table[48] = {}
vr_mem_stats_table[48].field_name = "vms_nexthop_object"
vr_mem_stats_table[48].ProtoField = ProtoField.int64
vr_mem_stats_table[48].base = base.DEC

vr_mem_stats_table[49] = {}
vr_mem_stats_table[49].field_name = "vms_nexthop_component_object"
vr_mem_stats_table[49].ProtoField = ProtoField.int64
vr_mem_stats_table[49].base = base.DEC

vr_mem_stats_table[50] = {}
vr_mem_stats_table[50].field_name = "vms_nexthop_req_list_object"
vr_mem_stats_table[50].ProtoField = ProtoField.int64
vr_mem_stats_table[50].base = base.DEC

vr_mem_stats_table[51] = {}
vr_mem_stats_table[51].field_name = "vms_nexthop_req_encap_object"
vr_mem_stats_table[51].ProtoField = ProtoField.int64
vr_mem_stats_table[51].base = base.DEC

vr_mem_stats_table[52] = {}
vr_mem_stats_table[52].field_name = "vms_nexthop_req_object"
vr_mem_stats_table[52].ProtoField = ProtoField.int64
vr_mem_stats_table[52].base = base.DEC

vr_mem_stats_table[53] = {}
vr_mem_stats_table[53].field_name = "vms_route_table_object"
vr_mem_stats_table[53].ProtoField = ProtoField.int64
vr_mem_stats_table[53].base = base.DEC

vr_mem_stats_table[54] = {}
vr_mem_stats_table[54].field_name = "vms_route_req_mac_object"
vr_mem_stats_table[54].ProtoField = ProtoField.int64
vr_mem_stats_table[54].base = base.DEC

vr_mem_stats_table[55] = {}
vr_mem_stats_table[55].field_name = "vms_timer_object"
vr_mem_stats_table[55].ProtoField = ProtoField.int64
vr_mem_stats_table[55].base = base.DEC

vr_mem_stats_table[56] = {}
vr_mem_stats_table[56].field_name = "vms_usock_object"
vr_mem_stats_table[56].ProtoField = ProtoField.int64
vr_mem_stats_table[56].base = base.DEC

vr_mem_stats_table[57] = {}
vr_mem_stats_table[57].field_name = "vms_usock_poll_object"
vr_mem_stats_table[57].ProtoField = ProtoField.int64
vr_mem_stats_table[57].base = base.DEC

vr_mem_stats_table[58] = {}
vr_mem_stats_table[58].field_name = "vms_usock_buf_object"
vr_mem_stats_table[58].ProtoField = ProtoField.int64
vr_mem_stats_table[58].base = base.DEC

vr_mem_stats_table[59] = {}
vr_mem_stats_table[59].field_name = "vms_usock_iovec_object"
vr_mem_stats_table[59].ProtoField = ProtoField.int64
vr_mem_stats_table[59].base = base.DEC

vr_mem_stats_table[60] = {}
vr_mem_stats_table[60].field_name = "vms_vrouter_req_object"
vr_mem_stats_table[60].ProtoField = ProtoField.int64
vr_mem_stats_table[60].base = base.DEC

vr_mem_stats_table[61] = {}
vr_mem_stats_table[61].field_name = "vms_interface_fat_flow_config_object"
vr_mem_stats_table[61].ProtoField = ProtoField.int64
vr_mem_stats_table[61].base = base.DEC

vr_mem_stats_table[62] = {}
vr_mem_stats_table[62].field_name = "vms_qos_map_object"
vr_mem_stats_table[62].ProtoField = ProtoField.int64
vr_mem_stats_table[62].base = base.DEC

vr_mem_stats_table[63] = {}
vr_mem_stats_table[63].field_name = "vms_fc_object"
vr_mem_stats_table[63].ProtoField = ProtoField.int64
vr_mem_stats_table[63].base = base.DEC

vr_mem_stats_table[64] = {}
vr_mem_stats_table[64].field_name = "vms_interface_mirror_meta_object"
vr_mem_stats_table[64].ProtoField = ProtoField.int64
vr_mem_stats_table[64].base = base.DEC

vr_mem_stats_table[65] = {}
vr_mem_stats_table[65].field_name = "vms_interface_req_mirror_meta_object"
vr_mem_stats_table[65].ProtoField = ProtoField.int64
vr_mem_stats_table[65].base = base.DEC

vr_mem_stats_table[66] = {}
vr_mem_stats_table[66].field_name = "vms_interface_bridge_lock_object"
vr_mem_stats_table[66].ProtoField = ProtoField.int64
vr_mem_stats_table[66].base = base.DEC

vr_mem_stats_table[67] = {}
vr_mem_stats_table[67].field_name = "vms_interface_queue_object"
vr_mem_stats_table[67].ProtoField = ProtoField.int64
vr_mem_stats_table[67].base = base.DEC

vr_mem_stats_table[68] = {}
vr_mem_stats_table[68].field_name = "vms_interface_req_pbb_mac_object"
vr_mem_stats_table[68].ProtoField = ProtoField.int64
vr_mem_stats_table[68].base = base.DEC

vr_mem_stats_table[69] = {}
vr_mem_stats_table[69].field_name = "vms_nexthop_req_bmac_object"
vr_mem_stats_table[69].ProtoField = ProtoField.int64
vr_mem_stats_table[69].base = base.DEC

vr_mem_stats_table[70] = {}
vr_mem_stats_table[70].field_name = "vms_interface_req_bridge_id_object"
vr_mem_stats_table[70].ProtoField = ProtoField.int64
vr_mem_stats_table[70].base = base.DEC

vr_mem_stats_table[71] = {}
vr_mem_stats_table[71].field_name = "vms_interface_fat_flow_ipv4_exclude_list_object"
vr_mem_stats_table[71].ProtoField = ProtoField.int64
vr_mem_stats_table[71].base = base.DEC

vr_mem_stats_table[72] = {}
vr_mem_stats_table[72].field_name = "vms_interface_fat_flow_ipv6_exclude_list_object"
vr_mem_stats_table[72].ProtoField = ProtoField.int64
vr_mem_stats_table[72].base = base.DEC

