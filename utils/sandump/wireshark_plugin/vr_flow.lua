vr_flow_action = {}
vr_flow_action["0x0000"] = "Drop"
vr_flow_action["0x0001"] = "Hold"
vr_flow_action["0x0002"] = "Forward"
vr_flow_action["0x0003"] = "Nat"

vr_flow_flags = {}
vr_flow_flags["0x0001"] = "VR_FLOW_FLAG_ACTIVE"
vr_flow_flags["0x0100"] = "VR_FLOW_FLAG_MODIFIED"
vr_flow_flags["0x0200"] = "VR_FLOW_FLAG_NEW_FLOW"
vr_flow_flags["0x0400"] = "VR_FLOW_FLAG_EVICT_CANDIDATE"
vr_flow_flags["0x0800"] = "VR_FLOW_FLAG_EVICTED"
vr_flow_flags["0x1000"] = "VR_RFLOW_VALID"
vr_flow_flags["0x2000"] = "VR_FLOW_FLAG_MIRROR"
vr_flow_flags["0x4000"] = "VR_FLOW_FLAG_VRFT"
vr_flow_flags["0x8000"] = "VR_FLOW_FLAG_LINK_LOCAL"

vr_flow_flags1 = {}
vr_flow_flags1["0x1000"] = "VR_FLOW_FLAG1_HBS_LEFT"
vr_flow_flags1["0x2000"] = "VR_FLOW_FLAG1_HBS_RIGHT"

vr_flow_extflags = {}
vr_flow_extflags["0x0001"] = "VR_FLOW_EXT_FLAG_FORCE_EVICT"
vr_flow_extflags["0x0002"] = "VR_FLOW_EXT_FLAG_MOCK_SRC_UDP"

vr_flow_table = {}

vr_flow_table[1] = {}
vr_flow_table[1].field_name = "vr_flow_fr_op"
vr_flow_table[1].ProtoField = ProtoField.int8
vr_flow_table[1].base = base.DEC
vr_flow_table[1].append_value = {
                branch = {
                             prepend = ": ",
                             value = function (val) return flow_op[val] end
                         },
                subtree = {
                             prepend = ", Operation: ",
                             value = function (val) return flow_op[val] end
                          }}
vr_flow_table[1].info_col = {prepend = "Operation: "}
vr_flow_table[1].show_when_zero = true

vr_flow_table[2] = {}
vr_flow_table[2].field_name = "fr_rid"
vr_flow_table[2].ProtoField = ProtoField.int16
vr_flow_table[2].base = base.DEC

vr_flow_table[3] = {}
vr_flow_table[3].field_name = "fr_index"
vr_flow_table[3].ProtoField = ProtoField.int32
vr_flow_table[3].base = base.DEC
vr_flow_table[3].append_value = {
                subtree = {
                              prepend = ", ID: ",
                              value = function (val) return tostring(val) end
                          }}
vr_flow_table[3].info_col = {prepend = " ID: "}
vr_flow_table[3].show_when_zero = true

vr_flow_table[4] = {}
vr_flow_table[4].field_name = "fr_action"
vr_flow_table[4].ProtoField = ProtoField.uint16
vr_flow_table[4].base = base.HEX
vr_flow_table[4].append_value = {
          branch = {
                      prepend = ": ",
                      value = function (val) return vr_flow_action[val] end
                   },
          subtree = {
                      prepend = ", Action: ",
                      value = function (val) return vr_flow_action[val] end
                    }}
vr_flow_table[4].info_col = {prepend = "Action: "}
vr_flow_table[4].show_when_zero = true

vr_flow_table[5] = {}
vr_flow_table[5].field_name = "fr_flags"
vr_flow_table[5].ProtoField = ProtoField.uint16
vr_flow_table[5].base = base.HEX
vr_flow_table[5].decode_bits = vr_flow_flags

vr_flow_table[6] = {}
vr_flow_table[6].field_name = "fr_rindex"
vr_flow_table[6].ProtoField = ProtoField.int32
vr_flow_table[6].base = base.DEC

vr_flow_table[7] = {}
vr_flow_table[7].field_name = "fr_family"
vr_flow_table[7].ProtoField = ProtoField.int32
vr_flow_table[7].base = base.DEC
vr_flow_table[7].append_value = {
          branch = {
                      prepend = ": ",
                      value = function (val) return family[val] end
                   }}

vr_flow_table[8] = {}
vr_flow_table[8].field_name = "fr_flow_sip_u"
vr_flow_table[8].ProtoField = ProtoField.bytes
vr_flow_table[8].base = base.SPACE
vr_flow_table[8].info_col = {prepend = "Sip_u: "}
vr_flow_table[8].depends_on = "fr_family"

vr_flow_table[9] = {}
vr_flow_table[9].field_name = "fr_flow_sip_l"
vr_flow_table[9].ProtoField = ProtoField.bytes
vr_flow_table[9].base = base.SPACE
vr_flow_table[9].info_col = {prepend = "Sip_l: "}
vr_flow_table[9].depends_on = "fr_family"

vr_flow_table[10] = {}
vr_flow_table[10].field_name = "fr_flow_dip_u"
vr_flow_table[10].ProtoField = ProtoField.bytes
vr_flow_table[10].base = base.SPACE
vr_flow_table[10].info_col = {prepend = "Dip_u: "}
vr_flow_table[10].depends_on = "fr_family"

vr_flow_table[11] = {}
vr_flow_table[11].field_name = "fr_flow_dip_l"
vr_flow_table[11].ProtoField = ProtoField.bytes
vr_flow_table[11].base = base.SPACE
vr_flow_table[11].info_col = {prepend = "Dip_l: "}
vr_flow_table[11].depends_on = "fr_family"

vr_flow_table[12] = {}
vr_flow_table[12].field_name = "fr_flow_sport"
vr_flow_table[12].ProtoField = ProtoField.uint16
vr_flow_table[12].base = base.DEC
vr_flow_table[12].info_col = {prepend = "Sport: "}

vr_flow_table[13] = {}
vr_flow_table[13].field_name = "fr_flow_dport"
vr_flow_table[13].ProtoField = ProtoField.uint16
vr_flow_table[13].base = base.DEC
vr_flow_table[13].info_col = {prepend = "Dport: "}

vr_flow_table[14] = {}
vr_flow_table[14].field_name = "fr_flow_proto"
vr_flow_table[14].ProtoField = ProtoField.int8
vr_flow_table[14].base = base.DEC

vr_flow_table[15] = {}
vr_flow_table[15].field_name = "fr_flow_vrf"
vr_flow_table[15].ProtoField = ProtoField.uint16
vr_flow_table[15].base = base.DEC

vr_flow_table[16] = {}
vr_flow_table[16].field_name = "fr_flow_dvrf"
vr_flow_table[16].ProtoField = ProtoField.uint16
vr_flow_table[16].base = base.DEC

vr_flow_table[17] = {}
vr_flow_table[17].field_name = "fr_mir_id"
vr_flow_table[17].ProtoField = ProtoField.uint16
vr_flow_table[17].base = base.DEC

vr_flow_table[18] = {}
vr_flow_table[18].field_name = "fr_sec_mir_id"
vr_flow_table[18].ProtoField = ProtoField.uint16
vr_flow_table[18].base = base.DEC

vr_flow_table[19] = {}
vr_flow_table[19].field_name = "fr_mir_sip"
vr_flow_table[19].ProtoField = ProtoField.ipv4

vr_flow_table[20] = {}
vr_flow_table[20].field_name = "fr_mir_sport"
vr_flow_table[20].ProtoField = ProtoField.uint16
vr_flow_table[20].base = base.DEC

vr_flow_table[21] = {}
vr_flow_table[21].field_name = "fr_pcap_meta_data"
vr_flow_table[21].ProtoField = ProtoField.bytes
vr_flow_table[21].base = base.SPACE

vr_flow_table[22] = {}
vr_flow_table[22].field_name = "fr_mir_vrf"
vr_flow_table[22].ProtoField = ProtoField.uint16
vr_flow_table[22].base = base.DEC

vr_flow_table[23] = {}
vr_flow_table[23].field_name = "fr_ecmp_nh_index"
vr_flow_table[23].ProtoField = ProtoField.uint32
vr_flow_table[23].base = base.DEC

vr_flow_table[24] = {}
vr_flow_table[24].field_name = "fr_src_nh_index"
vr_flow_table[24].ProtoField = ProtoField.uint32
vr_flow_table[24].base = base.DEC

vr_flow_table[25] = {}
vr_flow_table[25].field_name = "fr_flow_nh_id"
vr_flow_table[25].ProtoField = ProtoField.uint32
vr_flow_table[25].base = base.DEC

vr_flow_table[26] = {}
vr_flow_table[26].field_name = "fr_drop_reason"
vr_flow_table[26].ProtoField = ProtoField.uint16
vr_flow_table[26].base = base.DEC

vr_flow_table[27] = {}
vr_flow_table[27].field_name = "fr_gen_id"
vr_flow_table[27].ProtoField = ProtoField.int8
vr_flow_table[27].base = base.DEC

vr_flow_table[28] = {}
vr_flow_table[28].field_name = "fr_rflow_sip_u"
vr_flow_table[28].ProtoField = ProtoField.bytes
vr_flow_table[28].base = base.SPACE
vr_flow_table[28].depends_on = "fr_family"

vr_flow_table[29] = {}
vr_flow_table[29].field_name = "fr_rflow_sip_l"
vr_flow_table[29].ProtoField = ProtoField.bytes
vr_flow_table[29].base = base.SPACE
vr_flow_table[29].depends_on = "fr_family"

vr_flow_table[30] = {}
vr_flow_table[30].field_name = "fr_rflow_dip_u"
vr_flow_table[30].ProtoField = ProtoField.bytes
vr_flow_table[30].base = base.SPACE
vr_flow_table[30].depends_on = "fr_family"

vr_flow_table[31] = {}
vr_flow_table[31].field_name = "fr_rflow_dip_l"
vr_flow_table[31].ProtoField = ProtoField.bytes
vr_flow_table[31].base = base.SPACE
vr_flow_table[31].depends_on = "fr_family"

vr_flow_table[32] = {}
vr_flow_table[32].field_name = "fr_rflow_nh_id"
vr_flow_table[32].ProtoField = ProtoField.uint32
vr_flow_table[32].base = base.DEC

vr_flow_table[33] = {}
vr_flow_table[33].field_name = "fr_flow_sport"
vr_flow_table[33].ProtoField = ProtoField.uint16
vr_flow_table[33].base = base.DEC

vr_flow_table[34] = {}
vr_flow_table[34].field_name = "fr_flow_dport"
vr_flow_table[34].ProtoField = ProtoField.uint16
vr_flow_table[34].base = base.DEC

vr_flow_table[35] = {}
vr_flow_table[35].field_name = "fr_qos_id"
vr_flow_table[35].ProtoField = ProtoField.uint16
vr_flow_table[35].base = base.DEC

vr_flow_table[36] = {}
vr_flow_table[36].field_name = "fr_ttl"
vr_flow_table[36].ProtoField = ProtoField.int8
vr_flow_table[36].base = base.DEC

vr_flow_table[37] = {}
vr_flow_table[37].field_name = "fr_extflags"
vr_flow_table[37].ProtoField = ProtoField.uint16
vr_flow_table[37].base = base.HEX
vr_flow_table[37].decode_bits = vr_flow_extflags

vr_flow_table[38] = {}
vr_flow_table[38].field_name = "fr_flags1"
vr_flow_table[38].ProtoField = ProtoField.uint16
vr_flow_table[38].base = base.HEX
vr_flow_table[38].decode_bits = vr_flow_flags1
