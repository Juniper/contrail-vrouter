vr_info_table = {}

vr_info_table[1] = {}
vr_info_table[1].field_name = "vr_info_h_op"
vr_info_table[1].ProtoField = ProtoField.int8
vr_info_table[1].base = base.DEC
vr_info_table[1].append_value = {
              branch = {
                          prepend = ": ",
                          value = function (val) return sandesh_op[val] end
                       },
              subtree = {
                          prepend = ", Operation: ",
                          value = function (val) return sandesh_op[val] end
                        }}
vr_info_table[1].info_col = {prepend = "Operation: "}
vr_info_table[1].show_when_zero = true

vr_info_table[2] = {}
vr_info_table[2].field_name = "vdu_rid"
vr_info_table[2].ProtoField = ProtoField.int16
vr_info_table[2].base = base.DEC

vr_info_table[3] = {}
vr_info_table[3].field_name = "vdu_index"
vr_info_table[3].ProtoField = ProtoField.int16
vr_info_table[3].base = base.DEC
vr_info_table[3].info_col = {prepend = "ID: "}
vr_info_table[3].show_when_zero = true
vr_info_table[3].append_value = {
             subtree = {
                          prepend = ", ID: ",
                          value = function (val) return tostring(val) end
                       }}

vr_info_table[4] = {}
vr_info_table[4].field_name = "vdu_buff_table_id"
vr_info_table[4].ProtoField = ProtoField.int16
vr_info_table[4].base = base.DEC

vr_info_table[5] = {}
vr_info_table[5].field_name = "vdu_marker"
vr_info_table[5].ProtoField = ProtoField.int16
vr_info_table[5].base = base.DEC

vr_info_table[6] = {}
vr_info_table[6].field_name = "vdu_msginfo"
vr_info_table[6].ProtoField = ProtoField.int16
vr_info_table[6].base = base.DEC

vr_info_table[7] = {}
vr_info_table[7].field_name = "vdu_outbufsz"
vr_info_table[7].ProtoField = ProtoField.int32
vr_info_table[7].base = base.DEC

vr_info_table[8] = {}
vr_info_table[8].field_name = "vdu_inbuf"
vr_info_table[8].ProtoField = ProtoField.string

vr_info_table[9] = {}
vr_info_table[9].field_name = "vdu_proc_info"
vr_info_table[9].ProtoField = ProtoField.string
