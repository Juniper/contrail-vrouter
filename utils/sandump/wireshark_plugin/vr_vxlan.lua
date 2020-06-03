vr_vxlan_table = {}

vr_vxlan_table[1] = {}
vr_vxlan_table[1].field_name = "vr_vxlan_h_op"
vr_vxlan_table[1].ProtoField = ProtoField.int8
vr_vxlan_table[1].base = base.DEC
vr_vxlan_table[1].append_value = {
       branch = {
                   prepend = ": ",
                   value = function (val) return sandesh_op[val] end
                },
       subtree = {
                   prepend = ", Operation: ",
                   value = function (val) return sandesh_op[val] end
                 }}
vr_vxlan_table[1].info_col = {prepend = "Operation: "}
vr_vxlan_table[1].show_when_zero = true


vr_vxlan_table[2] = {}
vr_vxlan_table[2].field_name = "vxlanr_rid"
vr_vxlan_table[2].ProtoField = ProtoField.int16
vr_vxlan_table[2].base = base.DEC

vr_vxlan_table[3] = {}
vr_vxlan_table[3].field_name = "vxlanr_vnid"
vr_vxlan_table[3].ProtoField = ProtoField.int32
vr_vxlan_table[3].base = base.DEC
vr_vxlan_table[3].info_col = {prepend = "VNID: "}
vr_vxlan_table[3].show_when_zero = true
vr_vxlan_table[3].append_value = {
       subtree = {
                    prepend = ", VNID: ",
                    value = function (val) return tostring(val) end
                 }}

vr_vxlan_table[4] = {}
vr_vxlan_table[4].field_name = "vxlanr_nhid"
vr_vxlan_table[4].ProtoField = ProtoField.int32
vr_vxlan_table[4].base = base.DEC
vr_vxlan_table[4].info_col = {prepend = "NHID: "}
vr_vxlan_table[4].show_when_zero = true
vr_vxlan_table[4].append_value = {
       subtree = {
                    prepend = ", NHID: " ,
                    value = function (val) return tostring(val) end
                 }}
