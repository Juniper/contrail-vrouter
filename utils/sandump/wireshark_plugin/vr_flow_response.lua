vr_flow_resp_flags = {}
vr_flow_resp_flags["0x0001"] = "VR_FLOW_RESP_FLAG_DELETED"

vr_flow_resp_table = {}

vr_flow_resp_table[1] = {}
vr_flow_resp_table[1].field_name = "fresp_op"
vr_flow_resp_table[1].ProtoField = ProtoField.int8
vr_flow_resp_table[1].base = base.DEC
vr_flow_resp_table[1].append_value = {
                branch = {
                            prepend = ": ",
                            value = function (val) return flow_op[val] end
                         },
                subtree = {
                            prepend = ", Operation: ",
                            value = function (val) return flow_op[val] end
                          }}
vr_flow_resp_table[1].info_col = {prepend = "Operation: "}
vr_flow_resp_table[1].show_when_zero = true

vr_flow_resp_table[2] = {}
vr_flow_resp_table[2].field_name = "fresp_rid"
vr_flow_resp_table[2].ProtoField = ProtoField.uint16
vr_flow_resp_table[2].base = base.DEC

vr_flow_resp_table[3] = {}
vr_flow_resp_table[3].field_name = "fresp_flags"
vr_flow_resp_table[3].ProtoField = ProtoField.uint16
vr_flow_resp_table[3].base = base.HEX
vr_flow_resp_table[3].decode_bits = vr_flow_resp_flags

vr_flow_resp_table[4] = {}
vr_flow_resp_table[4].field_name = "fresp_index"
vr_flow_resp_table[4].ProtoField = ProtoField.uint32
vr_flow_resp_table[4].base = base.DEC
vr_flow_resp_table[4].append_value = {
                subtree = {
                             prepend = ", ID: ",
                             value = function (val) return tostring(val) end
                          }}
vr_flow_resp_table[4].info_col = {prepend = " ID: "}
vr_flow_resp_table[4].show_when_zero = true

vr_flow_resp_table[5] = {}
vr_flow_resp_table[5].field_name = "fresp_bytes"
vr_flow_resp_table[5].ProtoField = ProtoField.uint32
vr_flow_resp_table[5].base = base.HEX

vr_flow_resp_table[6] = {}
vr_flow_resp_table[6].field_name = "fresp_packets"
vr_flow_resp_table[6].ProtoField = ProtoField.uint32
vr_flow_resp_table[6].base = base.DEC

vr_flow_resp_table[7] = {}
vr_flow_resp_table[7].field_name = "fresp_stats_oflow"
vr_flow_resp_table[7].ProtoField = ProtoField.uint32
vr_flow_resp_table[7].base = base.DEC

vr_flow_resp_table[8] = {}
vr_flow_resp_table[8].field_name = "fresp_gen_id"
vr_flow_resp_table[8].ProtoField = ProtoField.int8
vr_flow_resp_table[8].base = base.DEC

