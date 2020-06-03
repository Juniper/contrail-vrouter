vr_drop_stats_table = {}

vr_drop_stats_table[1] = {}
vr_drop_stats_table[1].field_name = "vr_drop_stats_h_op"
vr_drop_stats_table[1].ProtoField = ProtoField.int8
vr_drop_stats_table[1].base = base.DEC
vr_drop_stats_table[1].append_value = {
              branch = {
                          prepend = ": " ,
                          value = function (val) return sandesh_op[val] end
                       },
              subtree = {
                          prepend = ", Operation: ",
                          value = function (val) return sandesh_op[val] end
                        }}
vr_drop_stats_table[1].info_col = {prepend = "Operation: "}
vr_drop_stats_table[1].show_when_zero = true

vr_drop_stats_table[2] = {}
vr_drop_stats_table[2].field_name = "vds_rid"
vr_drop_stats_table[2].ProtoField = ProtoField.int64
vr_drop_stats_table[2].base = base.DEC

vr_drop_stats_table[3] = {}
vr_drop_stats_table[3].field_name = "vds_core"
vr_drop_stats_table[3].ProtoField = ProtoField.int64
vr_drop_stats_table[3].base = base.DEC
vr_drop_stats_table[3].append_value = {
              subtree = {
                           prepend = ", Core: " ,
                           value = function (val) return tostring(val) end
                        }}
vr_drop_stats_table[3].info_col = {prepend = "Core: "}
vr_drop_stats_table[3].show_when_zero = true

vr_drop_stats_table[4] = {}
vr_drop_stats_table[4].field_name = "vds_discard"
vr_drop_stats_table[4].ProtoField = ProtoField.int64
vr_drop_stats_table[4].base = base.DEC

vr_drop_stats_table[5] = {}
vr_drop_stats_table[5].field_name = "vds_pcpu_stats_failure_status"
vr_drop_stats_table[5].ProtoField = ProtoField.int8

vr_drop_stats_table[6] = {}
vr_drop_stats_table[6].field_name = "vds_pull"
vr_drop_stats_table[6].ProtoField = ProtoField.int64
vr_drop_stats_table[6].base = base.DEC

vr_drop_stats_table[7] = {}
vr_drop_stats_table[7].field_name = "vds_invalid_if"
vr_drop_stats_table[7].ProtoField = ProtoField.int64
vr_drop_stats_table[7].base = base.DEC

vr_drop_stats_table[8] = {}
vr_drop_stats_table[8].field_name = "vds_invalid_arp"
vr_drop_stats_table[8].ProtoField = ProtoField.int64
vr_drop_stats_table[8].base = base.DEC

vr_drop_stats_table[9] = {}
vr_drop_stats_table[9].field_name = "vds_trap_no_if"
vr_drop_stats_table[9].ProtoField = ProtoField.int64
vr_drop_stats_table[9].base = base.DEC

vr_drop_stats_table[10] = {}
vr_drop_stats_table[10].field_name = "vds_nowhere_to_go"
vr_drop_stats_table[10].ProtoField = ProtoField.int64
vr_drop_stats_table[10].base = base.DEC

vr_drop_stats_table[11] = {}
vr_drop_stats_table[11].field_name = "vds_flow_queue_limit_exceeded"
vr_drop_stats_table[11].ProtoField = ProtoField.int64
vr_drop_stats_table[11].base = base.DEC

vr_drop_stats_table[12] = {}
vr_drop_stats_table[12].field_name = "vds_flow_no_memory"
vr_drop_stats_table[12].ProtoField = ProtoField.int64
vr_drop_stats_table[12].base = base.DEC

vr_drop_stats_table[13] = {}
vr_drop_stats_table[13].field_name = "vds_flow_invalid_protocol"
vr_drop_stats_table[13].ProtoField = ProtoField.int64
vr_drop_stats_table[13].base = base.DEC

vr_drop_stats_table[14] = {}
vr_drop_stats_table[14].field_name = "vds_flow_nat_no_rflow"
vr_drop_stats_table[14].ProtoField = ProtoField.int64
vr_drop_stats_table[14].base = base.DEC

vr_drop_stats_table[15] = {}
vr_drop_stats_table[15].field_name = "vds_flow_action_drop"
vr_drop_stats_table[15].ProtoField = ProtoField.int64
vr_drop_stats_table[15].base = base.DEC

vr_drop_stats_table[16] = {}
vr_drop_stats_table[16].field_name = "vds_flow_action_invalid"
vr_drop_stats_table[16].ProtoField = ProtoField.int64
vr_drop_stats_table[16].base = base.DEC

vr_drop_stats_table[17] = {}
vr_drop_stats_table[17].field_name = "vds_flow_unusable"
vr_drop_stats_table[17].ProtoField = ProtoField.int64
vr_drop_stats_table[17].base = base.DEC

vr_drop_stats_table[18] = {}
vr_drop_stats_table[18].field_name = "vds_flow_table_full"
vr_drop_stats_table[18].ProtoField = ProtoField.int64
vr_drop_stats_table[18].base = base.DEC

vr_drop_stats_table[19] = {}
vr_drop_stats_table[19].field_name = "vds_interface_tx_discard"
vr_drop_stats_table[19].ProtoField = ProtoField.int64
vr_drop_stats_table[19].base = base.DEC

vr_drop_stats_table[20] = {}
vr_drop_stats_table[20].field_name = "vds_interface_drop"
vr_drop_stats_table[20].ProtoField = ProtoField.int64
vr_drop_stats_table[20].base = base.DEC

vr_drop_stats_table[21] = {}
vr_drop_stats_table[21].field_name = "vds_duplicated"
vr_drop_stats_table[21].ProtoField = ProtoField.int64
vr_drop_stats_table[21].base = base.DEC

vr_drop_stats_table[22] = {}
vr_drop_stats_table[22].field_name = "vds_push"
vr_drop_stats_table[22].ProtoField = ProtoField.int64
vr_drop_stats_table[22].base = base.DEC

vr_drop_stats_table[23] = {}
vr_drop_stats_table[23].field_name = "vds_ttl_exceeded"
vr_drop_stats_table[23].ProtoField = ProtoField.int64
vr_drop_stats_table[23].base = base.DEC

vr_drop_stats_table[24] = {}
vr_drop_stats_table[24].field_name = "vds_invalid_nh"
vr_drop_stats_table[24].ProtoField = ProtoField.int64
vr_drop_stats_table[24].base = base.DEC

vr_drop_stats_table[25] = {}
vr_drop_stats_table[25].field_name = "vds_invalid_label"
vr_drop_stats_table[25].ProtoField = ProtoField.int64
vr_drop_stats_table[25].base = base.DEC

vr_drop_stats_table[26] = {}
vr_drop_stats_table[26].field_name = "vds_invalid_protocol"
vr_drop_stats_table[26].ProtoField = ProtoField.int64
vr_drop_stats_table[26].base = base.DEC

vr_drop_stats_table[27] = {}
vr_drop_stats_table[27].field_name = "vds_interface_rx_discard"
vr_drop_stats_table[27].ProtoField = ProtoField.int64
vr_drop_stats_table[27].base = base.DEC

vr_drop_stats_table[28] = {}
vr_drop_stats_table[28].field_name = "vds_invalid_mcast_source"
vr_drop_stats_table[28].ProtoField = ProtoField.int64
vr_drop_stats_table[28].base = base.DEC

vr_drop_stats_table[29] = {}
vr_drop_stats_table[29].field_name = "vds_head_alloc_fail"
vr_drop_stats_table[29].ProtoField = ProtoField.int64
vr_drop_stats_table[29].base = base.DEC

vr_drop_stats_table[30] = {}
vr_drop_stats_table[30].field_name = "vds_pcow_fail"
vr_drop_stats_table[30].ProtoField = ProtoField.int64
vr_drop_stats_table[30].base = base.DEC

vr_drop_stats_table[31] = {}
vr_drop_stats_table[31].field_name = "vds_mcast_df_bit"
vr_drop_stats_table[31].ProtoField = ProtoField.int64
vr_drop_stats_table[31].base = base.DEC

vr_drop_stats_table[32] = {}
vr_drop_stats_table[32].field_name = "vds_mcast_clone_fail"
vr_drop_stats_table[32].ProtoField = ProtoField.int64
vr_drop_stats_table[32].base = base.DEC

vr_drop_stats_table[33] = {}
vr_drop_stats_table[33].field_name = "vds_no_memory"
vr_drop_stats_table[33].ProtoField = ProtoField.int64
vr_drop_stats_table[33].base = base.DEC

vr_drop_stats_table[34] = {}
vr_drop_stats_table[34].field_name = "vds_rewrite_fail"
vr_drop_stats_table[34].ProtoField = ProtoField.int64
vr_drop_stats_table[34].base = base.DEC

vr_drop_stats_table[35] = {}
vr_drop_stats_table[35].field_name = "vds_misc"
vr_drop_stats_table[35].ProtoField = ProtoField.int64
vr_drop_stats_table[35].base = base.DEC

vr_drop_stats_table[36] = {}
vr_drop_stats_table[36].field_name = "vds_invalid_packet"
vr_drop_stats_table[36].ProtoField = ProtoField.int64
vr_drop_stats_table[36].base = base.DEC

vr_drop_stats_table[37] = {}
vr_drop_stats_table[37].field_name = "vds_cksum_err"
vr_drop_stats_table[37].ProtoField = ProtoField.int64
vr_drop_stats_table[37].base = base.DEC

vr_drop_stats_table[38] = {}
vr_drop_stats_table[38].field_name = "vds_no_fmd"
vr_drop_stats_table[38].ProtoField = ProtoField.int64
vr_drop_stats_table[38].base = base.DEC

vr_drop_stats_table[39] = {}
vr_drop_stats_table[39].field_name = "vds_cloned_original"
vr_drop_stats_table[39].ProtoField = ProtoField.int64
vr_drop_stats_table[39].base = base.DEC

vr_drop_stats_table[40] = {}
vr_drop_stats_table[40].field_name = "vds_invalid_vnid"
vr_drop_stats_table[40].ProtoField = ProtoField.int64
vr_drop_stats_table[40].base = base.DEC

vr_drop_stats_table[41] = {}
vr_drop_stats_table[41].field_name = "vds_frag_err"
vr_drop_stats_table[41].ProtoField = ProtoField.int64
vr_drop_stats_table[41].base = base.DEC

vr_drop_stats_table[42] = {}
vr_drop_stats_table[42].field_name = "vds_invalid_source"
vr_drop_stats_table[42].ProtoField = ProtoField.int64
vr_drop_stats_table[42].base = base.DEC

vr_drop_stats_table[43] = {}
vr_drop_stats_table[43].field_name = "vds_l2_no_route"
vr_drop_stats_table[43].ProtoField = ProtoField.int64
vr_drop_stats_table[43].base = base.DEC

vr_drop_stats_table[44] = {}
vr_drop_stats_table[44].field_name = "vds_fragment_queue_fail"
vr_drop_stats_table[44].ProtoField = ProtoField.int64
vr_drop_stats_table[44].base = base.DEC

vr_drop_stats_table[45] = {}
vr_drop_stats_table[45].field_name = "vds_vlan_fwd_tx"
vr_drop_stats_table[45].ProtoField = ProtoField.int64
vr_drop_stats_table[45].base = base.DEC

vr_drop_stats_table[46] = {}
vr_drop_stats_table[46].field_name = "vds_vlan_fwd_enq"
vr_drop_stats_table[46].ProtoField = ProtoField.int64
vr_drop_stats_table[46].base = base.DEC

vr_drop_stats_table[47] = {}
vr_drop_stats_table[47].field_name = "vds_drop_new_flow"
vr_drop_stats_table[47].ProtoField = ProtoField.int64
vr_drop_stats_table[47].base = base.DEC

vr_drop_stats_table[48] = {}
vr_drop_stats_table[48].field_name = "vds_flow_evict"
vr_drop_stats_table[48].ProtoField = ProtoField.int64
vr_drop_stats_table[48].base = base.DEC

vr_drop_stats_table[49] = {}
vr_drop_stats_table[49].field_name = "vds_trap_original"
vr_drop_stats_table[49].ProtoField = ProtoField.int64
vr_drop_stats_table[49].base = base.DEC

vr_drop_stats_table[50] = {}
vr_drop_stats_table[50].field_name = "vds_leaf_to_leaf"
vr_drop_stats_table[50].ProtoField = ProtoField.int64
vr_drop_stats_table[50].base = base.DEC

vr_drop_stats_table[51] = {}
vr_drop_stats_table[51].field_name = "vds_bmac_isid_mismatch"
vr_drop_stats_table[51].ProtoField = ProtoField.int64
vr_drop_stats_table[51].base = base.DEC

vr_drop_stats_table[52] = {}
vr_drop_stats_table[52].field_name = "vds_pkt_loop"
vr_drop_stats_table[52].ProtoField = ProtoField.int64
vr_drop_stats_table[52].base = base.DEC

vr_drop_stats_table[53] = {}
vr_drop_stats_table[53].field_name = "vds_no_crypt_path"
vr_drop_stats_table[53].ProtoField = ProtoField.int64
vr_drop_stats_table[53].base = base.DEC

vr_drop_stats_table[54] = {}
vr_drop_stats_table[54].field_name = "vds_invalid_hbs_pkt"
vr_drop_stats_table[54].ProtoField = ProtoField.int64
vr_drop_stats_table[54].base = base.DEC

