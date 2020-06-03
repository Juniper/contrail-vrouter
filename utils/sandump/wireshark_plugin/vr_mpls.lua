vr_mpls_table = {}

vr_mpls_table[1] = {}
vr_mpls_table[1].field_name = "vr_mpls_h_op"
vr_mpls_table[1].ProtoField = ProtoField.int8
vr_mpls_table[1].base = base.DEC
vr_mpls_table[1].append_value = {
         branch = {
                     prepend = ": " ,
                     value = function (val) return sandesh_op[val] end
                  },
         subtree = {
                     prepend = ", Operation: ",
                     value = function (val) return sandesh_op[val] end
                   }}
vr_mpls_table[1].info_col = {prepend = "Operation: "}
vr_mpls_table[1].show_when_zero = true

vr_mpls_table[2] = {}
vr_mpls_table[2].field_name = "mr_label"
vr_mpls_table[2].ProtoField = ProtoField.int32
vr_mpls_table[2].base = base.DEC
vr_mpls_table[2].info_col = {prepend = "Label: "}
vr_mpls_table[2].show_when_zero = true
vr_mpls_table[2].append_value = {
          subtree = {
                       prepend = ", Label: ",
                       value = function (val) return tostring(val) end
                    }}

vr_mpls_table[3] = {}
vr_mpls_table[3].field_name = "mr_rid"
vr_mpls_table[3].ProtoField = ProtoField.int16
vr_mpls_table[3].base = base.DEC

vr_mpls_table[4] = {}
vr_mpls_table[4].field_name = "mr_nhid"
vr_mpls_table[4].ProtoField = ProtoField.int32
vr_mpls_table[4].base = base.DEC
vr_mpls_table[4].info_col = {prepend = " NHID: "}
vr_mpls_table[4].show_when_zero = true
vr_mpls_table[4].append_value = {
         subtree = {
                      prepend = ", NHID: " ,
                      value = function (val) return tostring(val) end
                   }}

vr_mpls_table[5] = {}
vr_mpls_table[5].field_name = "mr_marker"
vr_mpls_table[5].ProtoField = ProtoField.int32
vr_mpls_table[5].base = base.DEC

