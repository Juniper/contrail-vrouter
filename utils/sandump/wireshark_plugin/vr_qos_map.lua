vr_qos_map_table = {}

vr_qos_map_table[1] = {}
vr_qos_map_table[1].field_name = "vr_qos_map_h_op"
vr_qos_map_table[1].ProtoField = ProtoField.int8
vr_qos_map_table[1].base = base.DEC
vr_qos_map_table[1].append_value = {
        branch = {
                     prepend = ": ",
                     value = function (val) return sandesh_op[val] end
                 },
        subtree = {
                     prepend = ", Operation: ",
                     value = function (val) return sandesh_op[val] end
                  }}
vr_qos_map_table[1].info_col = {prepend = "Operation: "}
vr_qos_map_table[1].show_when_zero = true

vr_qos_map_table[2] = {}
vr_qos_map_table[2].field_name = "qmr_rid"
vr_qos_map_table[2].ProtoField = ProtoField.uint16
vr_qos_map_table[2].base = base.DEC

vr_qos_map_table[3] = {}
vr_qos_map_table[3].field_name = "qmr_id"
vr_qos_map_table[3].ProtoField = ProtoField.uint16
vr_qos_map_table[3].base = base.DEC
vr_qos_map_table[3].info_col = {prepend = "ID: "}
vr_qos_map_table[3].show_when_zero = true
vr_qos_map_table[3].append_value = {
        subtree = {
                     prepend = ", ID: " ,
                     value = function (val) return tostring(val) end
                  }}

vr_qos_map_table[4] = {}
vr_qos_map_table[4].field_name = "qmr_dscp"
vr_qos_map_table[4].ProtoField = ProtoField.bytes
vr_qos_map_table[4].base = base.SPACE

vr_qos_map_table[5] = {}
vr_qos_map_table[5].field_name = "qmr_dscp_fc_id"
vr_qos_map_table[5].ProtoField = ProtoField.bytes
vr_qos_map_table[5].base = base.SPACE

vr_qos_map_table[6] = {}
vr_qos_map_table[6].field_name = "qmr_mpls_qos"
vr_qos_map_table[6].ProtoField = ProtoField.bytes
vr_qos_map_table[6].base = base.SPACE

vr_qos_map_table[7] = {}
vr_qos_map_table[7].field_name = "qmr_mpls_qos_fc_id"
vr_qos_map_table[7].ProtoField = ProtoField.bytes
vr_qos_map_table[7].base = base.SPACE

vr_qos_map_table[8] = {}
vr_qos_map_table[8].field_name = "qmr_dotonep"
vr_qos_map_table[8].ProtoField = ProtoField.bytes
vr_qos_map_table[8].base = base.SPACE

vr_qos_map_table[9] = {}
vr_qos_map_table[9].field_name = "qmr_dotonep_fc_id"
vr_qos_map_table[9].ProtoField = ProtoField.bytes
vr_qos_map_table[9].base = base.SPACE

vr_qos_map_table[10] = {}
vr_qos_map_table[10].field_name = "qmr_marker"
vr_qos_map_table[10].ProtoField = ProtoField.int16
vr_qos_map_table[10].base = base.DEC
