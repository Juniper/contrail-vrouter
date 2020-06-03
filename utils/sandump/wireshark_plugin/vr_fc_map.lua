vr_fc_map_table = {}

vr_fc_map_table[1] = {}
vr_fc_map_table[1].field_name = "vr_fc_map_h_op"
vr_fc_map_table[1].ProtoField = ProtoField.int8
vr_fc_map_table[1].base = base.DEC
vr_fc_map_table[1].append_value = {
              branch = {
                          prepend = ": ",
                          value = function (val) return sandesh_op[val] end
                       },
              subtree = {
                          prepend = ", Operation: ",
                          value = function (val) return sandesh_op[val] end
                        }}
vr_fc_map_table[1].info_col = {prepend = "Operation: "}
vr_fc_map_table[1].show_when_zero = true

vr_fc_map_table[2] = {}
vr_fc_map_table[2].field_name = "fmr_rid"
vr_fc_map_table[2].ProtoField = ProtoField.uint16
vr_fc_map_table[2].base = base.DEC

vr_fc_map_table[3] = {}
vr_fc_map_table[3].field_name = "fmr_id"
vr_fc_map_table[3].ProtoField = ProtoField.bytes
vr_fc_map_table[3].base = base.SPACE
vr_fc_map_table[3].info_col = {prepend = "ID: "}
vr_fc_map_table[3].append_value = {
              subtree = {
                           prepend = ", ID: ",
                           value = function (val) return tostring(val) end
                        }}

vr_fc_map_table[4] = {}
vr_fc_map_table[4].field_name = "fmr_dscp"
vr_fc_map_table[4].ProtoField = ProtoField.bytes
vr_fc_map_table[4].base = base.SPACE

vr_fc_map_table[5] = {}
vr_fc_map_table[5].field_name = "fmr_mpls_qos"
vr_fc_map_table[5].ProtoField = ProtoField.bytes
vr_fc_map_table[5].base = base.SPACE

vr_fc_map_table[6] = {}
vr_fc_map_table[6].field_name = "fmr_dotonep"
vr_fc_map_table[6].ProtoField = ProtoField.bytes
vr_fc_map_table[6].base = base.SPACE

vr_fc_map_table[7] = {}
vr_fc_map_table[7].field_name = "fmr_queue_id"
vr_fc_map_table[7].ProtoField = ProtoField.bytes
vr_fc_map_table[7].base = base.SPACE

vr_fc_map_table[8] = {}
vr_fc_map_table[8].field_name = "fmr_marker"
vr_fc_map_table[8].ProtoField = ProtoField.int16
vr_fc_map_table[8].base = base.DEC
