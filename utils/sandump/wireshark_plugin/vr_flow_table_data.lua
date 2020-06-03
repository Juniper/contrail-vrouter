vr_flow_table_data_table = {}

vr_flow_table_data_table[1] = {}
vr_flow_table_data_table[1].field_name = "ftable_op"
vr_flow_table_data_table[1].ProtoField = ProtoField.int8
vr_flow_table_data_table[1].base = base.DEC
vr_flow_table_data_table[1].append_value = {
                 branch = {
                             prepend = ": ",
                             value = function (val) return flow_op[val] end
                          },
                 subtree = {
                             prepend = ", Operation: ",
                             value = function (val) return flow_op[val] end
                           }}
vr_flow_table_data_table[1].info_col = {prepend = "Operation: "}
vr_flow_table_data_table[1].show_when_zero = true

vr_flow_table_data_table[2] = {}
vr_flow_table_data_table[2].field_name = "ftable_rid"
vr_flow_table_data_table[2].ProtoField = ProtoField.uint16
vr_flow_table_data_table[2].base = base.DEC

vr_flow_table_data_table[3] = {}
vr_flow_table_data_table[3].field_name = "ftable_size"
vr_flow_table_data_table[3].ProtoField = ProtoField.uint32
vr_flow_table_data_table[3].base = base.DEC

vr_flow_table_data_table[4] = {}
vr_flow_table_data_table[4].field_name = "ftable_dev"
vr_flow_table_data_table[4].ProtoField = ProtoField.uint16
vr_flow_table_data_table[4].base = base.DEC

vr_flow_table_data_table[5] = {}
vr_flow_table_data_table[5].field_name = "ftable_file_path"
vr_flow_table_data_table[5].ProtoField = ProtoField.string

vr_flow_table_data_table[6] = {}
vr_flow_table_data_table[6].field_name = "ftable_used_entries"
vr_flow_table_data_table[6].ProtoField = ProtoField.uint64
vr_flow_table_data_table[6].base = base.DEC

vr_flow_table_data_table[7] = {}
vr_flow_table_data_table[7].field_name = "ftable_processed"
vr_flow_table_data_table[7].ProtoField = ProtoField.uint64
vr_flow_table_data_table[7].base = base.DEC

vr_flow_table_data_table[8] = {}
vr_flow_table_data_table[8].field_name = "ftable_deleted"
vr_flow_table_data_table[8].ProtoField = ProtoField.uint64
vr_flow_table_data_table[8].base = base.DEC

vr_flow_table_data_table[9] = {}
vr_flow_table_data_table[9].field_name = "ftable_added"
vr_flow_table_data_table[9].ProtoField = ProtoField.uint64
vr_flow_table_data_table[9].base = base.DEC

vr_flow_table_data_table[10] = {}
vr_flow_table_data_table[10].field_name = "ftable_created"
vr_flow_table_data_table[10].ProtoField = ProtoField.uint64
vr_flow_table_data_table[10].base = base.DEC

vr_flow_table_data_table[11] = {}
vr_flow_table_data_table[11].field_name = "ftable_changed"
vr_flow_table_data_table[11].ProtoField = ProtoField.uint64
vr_flow_table_data_table[11].base = base.DEC

vr_flow_table_data_table[12] = {}
vr_flow_table_data_table[12].field_name = "ftable_hold_oflows"
vr_flow_table_data_table[12].ProtoField = ProtoField.uint32
vr_flow_table_data_table[12].base = base.DEC

vr_flow_table_data_table[13] = {}
vr_flow_table_data_table[13].field_name = "ftable_cpus"
vr_flow_table_data_table[13].ProtoField = ProtoField.uint32
vr_flow_table_data_table[13].base = base.DEC

vr_flow_table_data_table[14] = {}
vr_flow_table_data_table[14].field_name = "ftable_oflow_entries"
vr_flow_table_data_table[14].ProtoField = ProtoField.uint32
vr_flow_table_data_table[14].base = base.DEC

vr_flow_table_data_table[15] = {}
vr_flow_table_data_table[15].field_name = "ftable_hold_stat"
vr_flow_table_data_table[15].ProtoField = ProtoField.bytes
vr_flow_table_data_table[15].base = base.SPACE

vr_flow_table_data_table[16] = {}
vr_flow_table_data_table[16].field_name = "ftable_burst_free_tokens"
vr_flow_table_data_table[16].ProtoField = ProtoField.uint32
vr_flow_table_data_table[16].base = base.DEC

vr_flow_table_data_table[17] = {}
vr_flow_table_data_table[17].field_name = "ftable_hold_entries"
vr_flow_table_data_table[17].ProtoField = ProtoField.uint32
vr_flow_table_data_table[17].base = base.DEC

