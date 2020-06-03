vr_response_table = {}

vr_response_table[1] = {}
vr_response_table[1].field_name = "vr_resp_h_op"
vr_response_table[1].ProtoField = ProtoField.int8
vr_response_table[1].base = base.DEC
vr_response_table[1].append_value = {
          branch = {
                       prepend = ": ",
                       value = function (val) return sandesh_op[val] end
                   },
          subtree = {
                       prepend = ", Operation: ",
                       value = function (val) return sandesh_op[val] end
                    }}

vr_response_table[2] = {}
vr_response_table[2].field_name = "resp_code"
vr_response_table[2].ProtoField = ProtoField.uint32
vr_response_table[2].base = base.HEX
vr_response_table[2].info_col = {prepend = "Response: "}
vr_response_table[2].show_when_zero = true
