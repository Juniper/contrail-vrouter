nhr_type = {}
nhr_type["0"] = "Dead"
nhr_type["1"] = "Rcv"
nhr_type["2"] = "Encap"
nhr_type["3"] = "Tunnel"
nhr_type["4"] = "Resolve"
nhr_type["5"] = "Discard"
nhr_type["6"] = "Composite"
nhr_type["7"] = "Vrf Translate"
nhr_type["8"] = "L2 Rcv"
nhr_type["9"] = "Max"


nhr_flags = {}
nhr_flags["0x00000001"] = "NH_FLAG_VALID"
nhr_flags["0x00000002"] = "NH_FLAG_POLICY_ENABLED"
nhr_flags["0x00000008"] = "NH_FLAG_TUNNEL_GRE"
nhr_flags["0x00000010"] = "NH_FLAG_TUNNEL_UDP"
nhr_flags["0x00000020"] = "NH_FLAG_MCAST"
nhr_flags["0x00000040"] = "NH_FLAG_TUNNEL_UDP_MPLS"
nhr_flags["0x00000080"] = "NH_FLAG_TUNNEL_VXLAN"
nhr_flags["0x00000100"] = "NH_FLAG_RELAXED_POLICY"
nhr_flags["0x00000200"] = "NH_FLAG_COMPOSITE_FABRIC"
nhr_flags["0x00000400"] = "NH_FLAG_COMPOSITE_ECMP"
nhr_flags["0x00000800"] = "NH_FLAG_COMPOSITE_LU_ECMP"
nhr_flags["0x00001000"] = "NH_FLAG_COMPOSITE_EVPN"
nhr_flags["0x00002000"] = "NH_FLAG_COMPOSITE_ENCAP"
nhr_flags["0x00004000"] = "NH_FLAG_COMPOSITE_TOR"
nhr_flags["0x00008000"] = "NH_FLAG_ROUTE_LOOKUP"
nhr_flags["0x00010000"] = "NH_FLAG_UNKNOWN_UC_FLOOD"
nhr_flags["0x00020000"] = "NH_FLAG_TUNNEL_SIP_COPY"
nhr_flags["0x00040000"] = "NH_FLAG_FLOW_LOOKUP"
nhr_flags["0x00080000"] = "NH_FLAG_TUNNEL_PBB"
nhr_flags["0x00100000"] = "NH_FLAG_MAC_LEARN"
nhr_flags["0x00200000"] = "NH_FLAG_ETREE_ROOT"
nhr_flags["0x00400000"] = "NH_FLAG_INDIRECT"
nhr_flags["0x00800000"] = "NH_FLAG_L2_CONTROL_DATA"
nhr_flags["0x01000000"] = "NH_FLAG_CRYPT_TRAFFIC"
nhr_flags["0x02000000"] = "NH_FLAG_L3_VXLAN"
nhr_flags["0x04000000"] = "NH_FLAG_TUNNEL_MPLS_O_MPLS"
nhr_flags["0x08000000"] = "NH_FLAG_VALIDATE_MCAST_SRC"


nh_req_table = {}

nh_req_table[1] = {}
nh_req_table[1].field_name = "nhr_h_op"
nh_req_table[1].ProtoField = ProtoField.int8
nh_req_table[1].base = base.DEC
nh_req_table[1].append_value = {
         branch = {
                     prepend = ": " ,
                     value = function (val) return sandesh_op[val] end
                  },
         subtree = {
                     prepend = ", Operation: ",
                     value = function (val) return sandesh_op[val] end
                   }}
nh_req_table[1].info_col = {prepend = "Operation: "}
nh_req_table[1].show_when_zero = true

nh_req_table[2] = {}
nh_req_table[2].field_name = "nhr_type"
nh_req_table[2].ProtoField = ProtoField.int8
nh_req_table[2].base = base.DEC
nh_req_table[2].append_value = {
         branch = {
                     prepend = ": ",
                     value = function (val) return nhr_type[val] end
                  },
         subtree = {
                     prepend = ", Type: ",
                     value = function (val) return nhr_type[val] end
                   }}
nh_req_table[2].show_when_zero = true

nh_req_table[3] = {}
nh_req_table[3].field_name = "nhr_family"
nh_req_table[3].ProtoField = ProtoField.int8
nh_req_table[3].base = base.DEC
nh_req_table[3].append_value = {
         branch = {
                     prepend = ": " ,
                     value = function (val) return family[val] end
                  }}

nh_req_table[4] = {}
nh_req_table[4].field_name = "nhr_id"
nh_req_table[4].ProtoField = ProtoField.int32
nh_req_table[4].base = base.DEC
nh_req_table[4].append_value = {
         subtree = {
                      prepend = ", ID: " ,
                      value = function (val) return tostring(val) end
                   }}
nh_req_table[4].info_col = {prepend = " Nexthop ID: "}
nh_req_table[4].show_when_zero = true

nh_req_table[5] = {}
nh_req_table[5].field_name = "nhr_rid"
nh_req_table[5].ProtoField = ProtoField.int32
nh_req_table[5].base = base.DEC

nh_req_table[6] = {}
nh_req_table[6].field_name = "nhr_encap_oif_id"
nh_req_table[6].ProtoField = ProtoField.int32
nh_req_table[6].base = base.DEC
nh_req_table[6].show_when_zero = true

nh_req_table[7] = {}
nh_req_table[7].field_name = "nhr_encap_len"
nh_req_table[7].ProtoField = ProtoField.int32
nh_req_table[7].base = base.DEC

nh_req_table[8] = {}
nh_req_table[8].field_name = "nhr_encap_family"
nh_req_table[8].ProtoField = ProtoField.uint32
nh_req_table[8].base = base.HEX

nh_req_table[9] = {}
nh_req_table[9].field_name = "nhr_vrf"
nh_req_table[9].ProtoField = ProtoField.int32
nh_req_table[9].base = base.DEC
nh_req_table[9].show_when_zero = true

nh_req_table[10] = {}
nh_req_table[10].field_name = "nhr_tun_sip"
nh_req_table[10].ProtoField = ProtoField.ipv4

nh_req_table[11] = {}
nh_req_table[11].field_name = "nhr_tun_dip"
nh_req_table[11].ProtoField = ProtoField.ipv4

nh_req_table[12] = {}
nh_req_table[12].field_name = "nhr_tun_sport"
nh_req_table[12].ProtoField = ProtoField.int16
nh_req_table[12].base = base.DEC

nh_req_table[13] = {}
nh_req_table[13].field_name = "nhr_tun_dport"
nh_req_table[13].ProtoField = ProtoField.int16
nh_req_table[13].base = base.DEC

nh_req_table[14] = {}
nh_req_table[14].field_name = "nhr_ref_cnt"
nh_req_table[14].ProtoField = ProtoField.int32
nh_req_table[14].base = base.DEC

nh_req_table[15] = {}
nh_req_table[15].field_name = "nhr_marker"
nh_req_table[15].ProtoField = ProtoField.int32
nh_req_table[15].base = base.DEC

nh_req_table[16] = {}
nh_req_table[16].field_name = "nhr_flags"
nh_req_table[16].ProtoField = ProtoField.uint32
nh_req_table[16].base = base.HEX
nh_req_table[16].decode_bits = nhr_flags

nh_req_table[17] = {}
nh_req_table[17].field_name = "nhr_encap"
nh_req_table[17].ProtoField = ProtoField.bytes
nh_req_table[17].base = base.SPACE

nh_req_table[18] = {}
nh_req_table[18].field_name = "nhr_nh_list"
nh_req_table[18].ProtoField = ProtoField.bytes
nh_req_table[18].base = base.SPACE

nh_req_table[19] = {}
nh_req_table[19].field_name = "nhr_label_list"
nh_req_table[19].ProtoField = ProtoField.bytes
nh_req_table[19].base = base.SPACE

nh_req_table[20] = {}
nh_req_table[20].field_name = "nhr_nh_count"
nh_req_table[20].ProtoField = ProtoField.int16
nh_req_table[20].base = base.DEC

nh_req_table[21] = {}
nh_req_table[21].field_name = "nhr_tun_sip6"
nh_req_table[21].ProtoField = ProtoField.ipv6

nh_req_table[22] = {}
nh_req_table[22].field_name = "nhr_tun_dip6"
nh_req_table[22].ProtoField = ProtoField.ipv6

nh_req_table[23] = {}
nh_req_table[23].field_name = "nhr_ecmp_config_hash"
nh_req_table[23].ProtoField = ProtoField.int8
nh_req_table[23].base = base.DEC

nh_req_table[24] = {}
nh_req_table[24].field_name = "nhr_pbb_mac"
nh_req_table[24].ProtoField = ProtoField.bytes
nh_req_table[24].base = base.COLON

nh_req_table[25] = {}
nh_req_table[25].field_name = "nhr_encap_crypt_oif_id"
nh_req_table[25].ProtoField = ProtoField.int32
nh_req_table[25].base = base.DEC

nh_req_table[26] = {}
nh_req_table[26].field_name = "nhr_crypt_traffic"
nh_req_table[26].ProtoField = ProtoField.int32
nh_req_table[26].base = base.DEC

nh_req_table[27] = {}
nh_req_table[27].field_name = "nhr_crypt_path_available"
nh_req_table[27].ProtoField = ProtoField.int32
nh_req_table[27].base = base.DEC

nh_req_table[28] = {}
nh_req_table[28].field_name = "nhr_rw_dst_mac"
nh_req_table[28].ProtoField = ProtoField.bytes
nh_req_table[28].base = base.COLON

nh_req_table[29] = {}
nh_req_table[29].field_name = "nhr_transport_label"
nh_req_table[29].ProtoField = ProtoField.uint32
nh_req_table[29].base = base.DEC
