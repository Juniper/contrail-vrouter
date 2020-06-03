rtr_label_flags = {}
rtr_label_flags["0x0001"] = "VR_RT_LABEL_VALID_FLAG"
rtr_label_flags["0x0002"] = "VR_RT_ARP_PROXY_FLAG"
rtr_label_flags["0x0004"] = "VR_RT_ARP_TRAP_FLAG"
rtr_label_flags["0x0008"] = "VR_RT_ARP_FLOOD_FLAG"

vr_route_table = {}

vr_route_table[1] = {}
vr_route_table[1].field_name = "vr_route_h_op"
vr_route_table[1].ProtoField = ProtoField.int8
vr_route_table[1].base = base.DEC
vr_route_table[1].append_value = {
        branch = {
                    prepend = ": ",
                    value = function (val) return sandesh_op[val] end
                 },
        subtree = {
                    prepend = ", Operation: ",
                    value = function (val) return sandesh_op[val] end
                  }}
vr_route_table[1].info_col = {prepend = "Operation: "}
vr_route_table[1].show_when_zero = true

vr_route_table[2] = {}
vr_route_table[2].field_name = "rtr_vrf_id"
vr_route_table[2].ProtoField = ProtoField.int32
vr_route_table[2].base = base.DEC

vr_route_table[3] = {}
vr_route_table[3].field_name = "rtr_family"
vr_route_table[3].ProtoField = ProtoField.int32
vr_route_table[3].base = base.DEC

vr_route_table[4] = {}
vr_route_table[4].field_name = "rtr_prefix"
vr_route_table[4].ProtoField = ProtoField.bytes
vr_route_table[4].base = base.SPACE

vr_route_table[5] = {}
vr_route_table[5].field_name = "rtr_prefix_len"
vr_route_table[5].ProtoField = ProtoField.int32
vr_route_table[5].base = base.DEC

vr_route_table[6] = {}
vr_route_table[6].field_name = "rtr_rid"
vr_route_table[6].ProtoField = ProtoField.int16
vr_route_table[6].base = base.DEC

vr_route_table[7] = {}
vr_route_table[7].field_name = "rtr_label_flags"
vr_route_table[7].ProtoField = ProtoField.uint16
vr_route_table[7].base = base.HEX
vr_route_table[7].decode_bits = rtr_label_flags

vr_route_table[8] = {}
vr_route_table[8].field_name = "rtr_label"
vr_route_table[8].ProtoField = ProtoField.int32
vr_route_table[8].base = base.DEC

vr_route_table[9] = {}
vr_route_table[9].field_name = "rtr_nh_id"
vr_route_table[9].ProtoField = ProtoField.int32
vr_route_table[9].base = base.DEC

vr_route_table[10] = {}
vr_route_table[10].field_name = "rtr_marker"
vr_route_table[10].ProtoField = ProtoField.bytes
vr_route_table[10].base = base.SPACE

vr_route_table[11] = {}
vr_route_table[11].field_name = "rtr_marker_plen"
vr_route_table[11].ProtoField = ProtoField.int32
vr_route_table[11].base = base.DEC

vr_route_table[12] = {}
vr_route_table[12].field_name = "rtr_mac"
vr_route_table[12].ProtoField = ProtoField.bytes
vr_route_table[12].base = base.COLON

vr_route_table[13] = {}
vr_route_table[13].field_name = "rtr_replace_plen"
vr_route_table[13].ProtoField = ProtoField.int32
vr_route_table[13].base = base.DEC

vr_route_table[14] = {}
vr_route_table[14].field_name = "rtr_index"
vr_route_table[14].ProtoField = ProtoField.int32
vr_route_table[14].base = base.DEC
