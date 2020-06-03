vrouter_ops_table = {}

vrouter_ops_table[1] = {}
vrouter_ops_table[1].field_name = "vrouter_ops_h_op"
vrouter_ops_table[1].ProtoField = ProtoField.int8
vrouter_ops_table[1].base = base.DEC
vrouter_ops_table[1].append_value = {
         branch = {
                      prepend = ": ",
                      value = function (val) return sandesh_op[val] end
                  },
         subtree = {
                      prepend = ", Operation: ",
                      value = function (val) return sandesh_op[val] end
                   }}
vrouter_ops_table[1].info_col = {prepend = "Operation: "}
vrouter_ops_table[1].show_when_zero = true

vrouter_ops_table[2] = {}
vrouter_ops_table[2].field_name = "vo_rid"
vrouter_ops_table[2].ProtoField = ProtoField.int32
vrouter_ops_table[2].base = base.DEC

vrouter_ops_table[3] = {}
vrouter_ops_table[3].field_name = "vo_mpls_labels"
vrouter_ops_table[3].ProtoField = ProtoField.int32
vrouter_ops_table[3].base = base.DEC

vrouter_ops_table[4] = {}
vrouter_ops_table[4].field_name = "vo_nexthops"
vrouter_ops_table[4].ProtoField = ProtoField.int32
vrouter_ops_table[4].base = base.DEC

vrouter_ops_table[5] = {}
vrouter_ops_table[5].field_name = "vo_bridge_entries"
vrouter_ops_table[5].ProtoField = ProtoField.int32
vrouter_ops_table[5].base = base.DEC

vrouter_ops_table[6] = {}
vrouter_ops_table[6].field_name = "vo_oflow_bridge_entries"
vrouter_ops_table[6].ProtoField = ProtoField.int32
vrouter_ops_table[6].base = base.DEC

vrouter_ops_table[7] = {}
vrouter_ops_table[7].field_name = "vo_flow_entries"
vrouter_ops_table[7].ProtoField = ProtoField.int32
vrouter_ops_table[7].base = base.DEC

vrouter_ops_table[8] = {}
vrouter_ops_table[8].field_name = "vo_oflow_entries"
vrouter_ops_table[8].ProtoField = ProtoField.int32
vrouter_ops_table[8].base = base.DEC

vrouter_ops_table[9] = {}
vrouter_ops_table[9].field_name = "vo_interfaces"
vrouter_ops_table[9].ProtoField = ProtoField.int32
vrouter_ops_table[9].base = base.DEC

vrouter_ops_table[10] = {}
vrouter_ops_table[10].field_name = "vo_mirror_entries"
vrouter_ops_table[10].ProtoField = ProtoField.int32
vrouter_ops_table[10].base = base.DEC

vrouter_ops_table[11] = {}
vrouter_ops_table[11].field_name = "vo_vrfs"
vrouter_ops_table[11].ProtoField = ProtoField.int32
vrouter_ops_table[11].base = base.DEC

vrouter_ops_table[12] = {}
vrouter_ops_table[12].field_name = "vo_build_info"
vrouter_ops_table[12].ProtoField = ProtoField.string

vrouter_ops_table[13] = {}
vrouter_ops_table[13].field_name = "vo_log_level"
vrouter_ops_table[13].ProtoField = ProtoField.uint32
vrouter_ops_table[13].base = base.DEC

vrouter_ops_table[14] = {}
vrouter_ops_table[14].field_name = "vo_log_type_enable"
vrouter_ops_table[14].ProtoField = ProtoField.bytes
vrouter_ops_table[14].base = base.SPACE

vrouter_ops_table[15] = {}
vrouter_ops_table[15].field_name = "vo_log_type_disable"
vrouter_ops_table[15].ProtoField = ProtoField.bytes
vrouter_ops_table[15].base = base.SPACE

vrouter_ops_table[16] = {}
vrouter_ops_table[16].field_name = "vo_perfr"
vrouter_ops_table[16].ProtoField = ProtoField.int32
vrouter_ops_table[16].base = base.DEC

vrouter_ops_table[17] = {}
vrouter_ops_table[17].field_name = "vo_perfs"
vrouter_ops_table[17].ProtoField = ProtoField.int32
vrouter_ops_table[17].base = base.DEC

vrouter_ops_table[18] = {}
vrouter_ops_table[18].field_name = "vo_from_vm_mss_adj"
vrouter_ops_table[18].ProtoField = ProtoField.int32
vrouter_ops_table[18].base = base.DEC

vrouter_ops_table[19] = {}
vrouter_ops_table[19].field_name = "vo_to_vm_mss_adj"
vrouter_ops_table[19].ProtoField = ProtoField.int32
vrouter_ops_table[19].base = base.DEC

vrouter_ops_table[20] = {}
vrouter_ops_table[20].field_name = "vo_perfr1"
vrouter_ops_table[20].ProtoField = ProtoField.int32
vrouter_ops_table[20].base = base.DEC

vrouter_ops_table[21] = {}
vrouter_ops_table[21].field_name = "vo_perfr2"
vrouter_ops_table[21].ProtoField = ProtoField.int32
vrouter_ops_table[21].base = base.DEC

vrouter_ops_table[22] = {}
vrouter_ops_table[22].field_name = "vo_perfr3"
vrouter_ops_table[22].ProtoField = ProtoField.int32
vrouter_ops_table[22].base = base.DEC

vrouter_ops_table[23] = {}
vrouter_ops_table[23].field_name = "vo_perfp"
vrouter_ops_table[23].ProtoField = ProtoField.int32
vrouter_ops_table[23].base = base.DEC

vrouter_ops_table[24] = {}
vrouter_ops_table[24].field_name = "vo_perfq1"
vrouter_ops_table[24].ProtoField = ProtoField.int32
vrouter_ops_table[24].base = base.DEC

vrouter_ops_table[25] = {}
vrouter_ops_table[25].field_name = "vo_perfq2"
vrouter_ops_table[25].ProtoField = ProtoField.int32
vrouter_ops_table[25].base = base.DEC

vrouter_ops_table[26] = {}
vrouter_ops_table[26].field_name = "vo_perfq3"
vrouter_ops_table[26].ProtoField = ProtoField.int32
vrouter_ops_table[26].base = base.DEC

vrouter_ops_table[27] = {}
vrouter_ops_table[27].field_name = "vo_udp_coff"
vrouter_ops_table[27].ProtoField = ProtoField.int32
vrouter_ops_table[27].base = base.DEC

vrouter_ops_table[28] = {}
vrouter_ops_table[28].field_name = "vo_flow_hold_limit"
vrouter_ops_table[28].ProtoField = ProtoField.int32
vrouter_ops_table[28].base = base.DEC

vrouter_ops_table[29] = {}
vrouter_ops_table[29].field_name = "vo_mudp"
vrouter_ops_table[29].ProtoField = ProtoField.int32
vrouter_ops_table[29].base = base.DEC

vrouter_ops_table[30] = {}
vrouter_ops_table[30].field_name = "vo_flow_used_entries"
vrouter_ops_table[30].ProtoField = ProtoField.uint32
vrouter_ops_table[30].base = base.DEC

vrouter_ops_table[31] = {}
vrouter_ops_table[31].field_name = "vo_flow_used_oentries"
vrouter_ops_table[31].ProtoField = ProtoField.uint32
vrouter_ops_table[31].base = base.DEC

vrouter_ops_table[32] = {}
vrouter_ops_table[32].field_name = "vo_bridge_used_entries"
vrouter_ops_table[32].ProtoField = ProtoField.uint32
vrouter_ops_table[32].base = base.DEC

vrouter_ops_table[33] = {}
vrouter_ops_table[33].field_name = "vo_bridge_used_oentries"
vrouter_ops_table[33].ProtoField = ProtoField.uint32
vrouter_ops_table[33].base = base.DEC

vrouter_ops_table[34] = {}
vrouter_ops_table[34].field_name = "vo_burst_tokens"
vrouter_ops_table[34].ProtoField = ProtoField.int32
vrouter_ops_table[34].base = base.DEC

vrouter_ops_table[35] = {}
vrouter_ops_table[35].field_name = "vo_burst_interval"
vrouter_ops_table[35].ProtoField = ProtoField.int32
vrouter_ops_table[35].base = base.DEC

vrouter_ops_table[36] = {}
vrouter_ops_table[36].field_name = "vo_burst_step"
vrouter_ops_table[36].ProtoField = ProtoField.int32
vrouter_ops_table[36].base = base.DEC

vrouter_ops_table[37] = {}
vrouter_ops_table[37].field_name = "vo_memory_alloc_checks"
vrouter_ops_table[37].ProtoField = ProtoField.int32
vrouter_ops_table[37].base = base.DEC

vrouter_ops_table[38] = {}
vrouter_ops_table[38].field_name = "vo_priority_tagging"
vrouter_ops_table[38].ProtoField = ProtoField.uint32
vrouter_ops_table[38].base = base.DEC

vrouter_ops_table[39] = {}
vrouter_ops_table[39].field_name = "vo_vif_bridge_entries"
vrouter_ops_table[39].ProtoField = ProtoField.int32
vrouter_ops_table[39].base = base.DEC

vrouter_ops_table[40] = {}
vrouter_ops_table[40].field_name = "vo_vif_oflow_bridge_entries"
vrouter_ops_table[40].ProtoField = ProtoField.int32
vrouter_ops_table[40].base = base.DEC

vrouter_ops_table[41] = {}
vrouter_ops_table[41].field_name = "vo_packet_dump"
vrouter_ops_table[41].ProtoField = ProtoField.int32
vrouter_ops_table[41].base = base.DEC

vrouter_ops_table[42] = {}
vrouter_ops_table[42].field_name = "vo_pkt_droplog_bufsz"
vrouter_ops_table[42].ProtoField = ProtoField.int32
vrouter_ops_table[42].base = base.DEC

vrouter_ops_table[43] = {}
vrouter_ops_table[43].field_name = "vo_pkt_droplog_buf_en"
vrouter_ops_table[43].ProtoField = ProtoField.int8

vrouter_ops_table[44] = {}
vrouter_ops_table[44].field_name = "vo_pkt_droplog_en"
vrouter_ops_table[44].ProtoField = ProtoField.int8

vrouter_ops_table[45] = {}
vrouter_ops_table[45].field_name = "vo_pkt_droplog_min_en"
vrouter_ops_table[45].ProtoField = ProtoField.int8

