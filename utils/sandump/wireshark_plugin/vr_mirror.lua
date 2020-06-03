mirr_flags = {}
mirr_flags["0x00000001"] = "VR_MIRROR_FLAG_DYNAMIC"
mirr_flags["0x00000002"] = "VR_MIRROR_FLAG_MARKED_DELETE"
mirr_flags["0x00000004"] = "VR_MIRROR_FLAG_HW_ASSISTED"

vr_mirror_table = {}

vr_mirror_table[1] = {}
vr_mirror_table[1].field_name = "vr_mirror_h_op"
vr_mirror_table[1].ProtoField = ProtoField.int8
vr_mirror_table[1].base = base.DEC
vr_mirror_table[1].append_value = {
            branch = {
                        prepend = ": ",
                        value = function (val) return sandesh_op[val] end
                     },
            subtree = {
                        prepend = ", Operation: ",
                        value = function (val) return sandesh_op[val] end
                      }}
vr_mirror_table[1].info_col = {prepend = "Operation: "}
vr_mirror_table[1].show_when_zero = true

vr_mirror_table[2] = {}
vr_mirror_table[2].field_name = "mirr_index"
vr_mirror_table[2].ProtoField = ProtoField.int16
vr_mirror_table[2].base = base.DEC
vr_mirror_table[2].info_col = {prepend = "ID: "}
vr_mirror_table[2].show_when_zero = true
vr_mirror_table[2].append_value = {
            subtree = {
                         prepend = ", ID: " ,
                         value = function (val) return tostring(val) end
                      }}

vr_mirror_table[3] = {}
vr_mirror_table[3].field_name = "mirr_rid"
vr_mirror_table[3].ProtoField = ProtoField.int16
vr_mirror_table[3].base = base.DEC

vr_mirror_table[4] = {}
vr_mirror_table[4].field_name = "mirr_nhid"
vr_mirror_table[4].ProtoField = ProtoField.int32
vr_mirror_table[4].base = base.DEC
vr_mirror_table[4].info_col = {prepend = "NHID: "}
vr_mirror_table[4].show_when_zero = true
vr_mirror_table[4].append_value = {
            subtree = {
                         prepend = ", NHID: " ,
                         value = function (val) return tostring(val) end
                      }}

vr_mirror_table[5] = {}
vr_mirror_table[5].field_name = "mirr_users"
vr_mirror_table[5].ProtoField = ProtoField.int32
vr_mirror_table[5].base = base.DEC

vr_mirror_table[6] = {}
vr_mirror_table[6].field_name = "mirr_flags"
vr_mirror_table[6].ProtoField = ProtoField.uint32
vr_mirror_table[6].base = base.HEX
vr_mirror_table[6].decode_bits = mirr_flags

vr_mirror_table[7] = {}
vr_mirror_table[7].field_name = "mirr_marker"
vr_mirror_table[7].ProtoField = ProtoField.int32
vr_mirror_table[7].base = base.DEC

vr_mirror_table[8] = {}
vr_mirror_table[8].field_name = "mirr_vni"
vr_mirror_table[8].ProtoField = ProtoField.int32
vr_mirror_table[8].base = base.DEC

vr_mirror_table[9] = {}
vr_mirror_table[9].field_name = "mirr_vlan"
vr_mirror_table[9].ProtoField = ProtoField.int16
vr_mirror_table[9].base = base.DEC


