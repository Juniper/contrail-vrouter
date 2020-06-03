vrf_flags = {}
vrf_flags["0x00000001"] = "VRF_FLAG_VALID"
vrf_flags["0x00000002"] = "VRF_FLAG_HBS_L_VALID"
vrf_flags["0x00000004"] = "VRF_FLAG_HBS_R_VALID"


vr_vrf_table = {}

vr_vrf_table[1] = {}
vr_vrf_table[1].field_name = "vr_vrf_h_op"
vr_vrf_table[1].ProtoField = ProtoField.int8
vr_vrf_table[1].base = base.DEC
vr_vrf_table[1].append_value = {
           branch = {
                       prepend = ": ",
                       value = function (val) return sandesh_op[val] end
                    },
           subtree = {
                       prepend = ", Operation: ",
                       value = function (val) return sandesh_op[val] end
                     }}
vr_vrf_table[1].info_col = {prepend = "Operation: "}
vr_vrf_table[1].show_when_zero = true

vr_vrf_table[2] = {}
vr_vrf_table[2].field_name = "vrf_rid"
vr_vrf_table[2].ProtoField = ProtoField.int16
vr_vrf_table[2].base = base.DEC

vr_vrf_table[3] = {}
vr_vrf_table[3].field_name = "vrf_idx"
vr_vrf_table[3].ProtoField = ProtoField.int32
vr_vrf_table[3].base = base.DEC
vr_vrf_table[3].info_col = {prepend = "ID: "}
vr_vrf_table[3].show_when_zero = true
vr_vrf_table[3].append_value = {
           subtree = {
                        prepend = ", ID: " ,
                        value = function (val) return tostring(val) end
                     }}

vr_vrf_table[4] = {}
vr_vrf_table[4].field_name = "vrf_flags"
vr_vrf_table[4].ProtoField = ProtoField.uint32
vr_vrf_table[4].base = base.HEX
vr_vrf_table[4].decode_bits = vrf_flags
vr_vrf_table[4].info_col = {prepend = "Flags: "}
vr_vrf_table[4].append_value = {
           subtree = {
                        prepend = ", Flags: " ,
                        value = function (val) return tostring(val) end
                     }}

vr_vrf_table[5] = {}
vr_vrf_table[5].field_name = "vrf_hbfl_vif_idx"
vr_vrf_table[5].ProtoField = ProtoField.int32
vr_vrf_table[5].base = base.DEC

vr_vrf_table[6] = {}
vr_vrf_table[6].field_name = "vrf_hbfr_vif_idx"
vr_vrf_table[6].ProtoField = ProtoField.int16
vr_vrf_table[6].base = base.DEC

vr_vrf_table[7] = {}
vr_vrf_table[7].field_name = "vrf_marker"
vr_vrf_table[7].ProtoField = ProtoField.int32
vr_vrf_table[7].base = base.DEC

