vr_bridge_table_data_table = {}

vr_bridge_table_data_table[1] = {}
vr_bridge_table_data_table[1].field_name = "btable_op"
vr_bridge_table_data_table[1].ProtoField = ProtoField.int8
vr_bridge_table_data_table[1].base = base.DEC
vr_bridge_table_data_table[1].append_value = {
         branch = {
                    prepend = ": ",
                    value = function (val) return sandesh_op[val] end
                  },
         subtree = {
                    prepend = ", Operation: ",
                    value = function (val) return sandesh_op[val] end
                   }}
vr_bridge_table_data_table[1].info_col = {prepend = "Operation: "}
vr_bridge_table_data_table[1].show_when_zero = true

vr_bridge_table_data_table[2] = {}
vr_bridge_table_data_table[2].field_name = "btable_rid"
vr_bridge_table_data_table[2].ProtoField = ProtoField.uint16
vr_bridge_table_data_table[2].base = base.DEC

vr_bridge_table_data_table[3] = {}
vr_bridge_table_data_table[3].field_name = "btable_size"
vr_bridge_table_data_table[3].ProtoField = ProtoField.uint32
vr_bridge_table_data_table[3].base = base.DEC

vr_bridge_table_data_table[4] = {}
vr_bridge_table_data_table[4].field_name = "btable_dev"
vr_bridge_table_data_table[4].ProtoField = ProtoField.uint16
vr_bridge_table_data_table[4].base = base.DEC

vr_bridge_table_data_table[5] = {}
vr_bridge_table_data_table[5].field_name = "btable_file_path"
vr_bridge_table_data_table[5].ProtoField = ProtoField.string

