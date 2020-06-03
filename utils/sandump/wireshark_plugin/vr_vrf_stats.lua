vr_vrf_stats_table = {}

vr_vrf_stats_table[1] = {}
vr_vrf_stats_table[1].field_name = "vr_vrf_stats_h_op"
vr_vrf_stats_table[1].ProtoField = ProtoField.int8
vr_vrf_stats_table[1].base = base.DEC
vr_vrf_stats_table[1].append_value = {
          branch = {
                      prepend = ": ",
                      value = function (val) return sandesh_op[val] end
                   },
          subtree = {
                      prepend = ", Operation: ",
                      value = function (val) return sandesh_op[val] end
                    }}
vr_vrf_stats_table[1].info_col = {prepend = "Operation: "}
vr_vrf_stats_table[1].show_when_zero = true

vr_vrf_stats_table[2] = {}
vr_vrf_stats_table[2].field_name = "vsr_rid"
vr_vrf_stats_table[2].ProtoField = ProtoField.int16
vr_vrf_stats_table[2].base = base.DEC

vr_vrf_stats_table[3] = {}
vr_vrf_stats_table[3].field_name = "vsr_family"
vr_vrf_stats_table[3].ProtoField = ProtoField.int16
vr_vrf_stats_table[3].base = base.DEC
vr_vrf_stats_table[3].append_value = {
          branch = {
                     prepend = ": ",
                     value = function (val) return family[val] end
                   }}

vr_vrf_stats_table[4] = {}
vr_vrf_stats_table[4].field_name = "vsr_type"
vr_vrf_stats_table[4].ProtoField = ProtoField.int16
vr_vrf_stats_table[4].base = base.DEC

vr_vrf_stats_table[5] = {}
vr_vrf_stats_table[5].field_name = "vsr_vrf"
vr_vrf_stats_table[5].ProtoField = ProtoField.int32
vr_vrf_stats_table[5].base = base.DEC
vr_vrf_stats_table[5].append_value = {
          subtree = {
                       prepend = ", Vrf: " ,
                       value = function (val) return tostring(val) end
                    }}
vr_vrf_stats_table[5].info_col = {prepend = "Vrf: "}
vr_vrf_stats_table[5].show_when_zero = true

vr_vrf_stats_table[6] = {}
vr_vrf_stats_table[6].field_name = "vsr_discards"
vr_vrf_stats_table[6].ProtoField = ProtoField.int64
vr_vrf_stats_table[6].base = base.DEC

vr_vrf_stats_table[7] = {}
vr_vrf_stats_table[7].field_name = "vsr_resolves"
vr_vrf_stats_table[7].ProtoField = ProtoField.int64
vr_vrf_stats_table[7].base = base.DEC

vr_vrf_stats_table[8] = {}
vr_vrf_stats_table[8].field_name = "vsr_receives"
vr_vrf_stats_table[8].ProtoField = ProtoField.int64
vr_vrf_stats_table[8].base = base.DEC

vr_vrf_stats_table[9] = {}
vr_vrf_stats_table[9].field_name = "vsr_ecmp_composites"
vr_vrf_stats_table[9].ProtoField = ProtoField.int64
vr_vrf_stats_table[9].base = base.DEC

vr_vrf_stats_table[10] = {}
vr_vrf_stats_table[10].field_name = "vsr_l2_mcast_composites"
vr_vrf_stats_table[10].ProtoField = ProtoField.int64
vr_vrf_stats_table[10].base = base.DEC

vr_vrf_stats_table[11] = {}
vr_vrf_stats_table[11].field_name = "vsr_fabric_composites"
vr_vrf_stats_table[11].ProtoField = ProtoField.int64
vr_vrf_stats_table[11].base = base.DEC

vr_vrf_stats_table[12] = {}
vr_vrf_stats_table[12].field_name = "vsr_udp_tunnels"
vr_vrf_stats_table[12].ProtoField = ProtoField.int64
vr_vrf_stats_table[12].base = base.DEC

vr_vrf_stats_table[13] = {}
vr_vrf_stats_table[13].field_name = "vsr_udp_mpls_tunnels"
vr_vrf_stats_table[13].ProtoField = ProtoField.int64
vr_vrf_stats_table[13].base = base.DEC

vr_vrf_stats_table[14] = {}
vr_vrf_stats_table[14].field_name = "vsr_gre_mpls_tunnels"
vr_vrf_stats_table[14].ProtoField = ProtoField.int64
vr_vrf_stats_table[14].base = base.DEC

vr_vrf_stats_table[15] = {}
vr_vrf_stats_table[15].field_name = "vsr_l2_encaps"
vr_vrf_stats_table[15].ProtoField = ProtoField.int64
vr_vrf_stats_table[15].base = base.DEC

vr_vrf_stats_table[16] = {}
vr_vrf_stats_table[16].field_name = "vsr_encaps"
vr_vrf_stats_table[16].ProtoField = ProtoField.int64
vr_vrf_stats_table[16].base = base.DEC

vr_vrf_stats_table[17] = {}
vr_vrf_stats_table[17].field_name = "vsr_marker"
vr_vrf_stats_table[17].ProtoField = ProtoField.int16
vr_vrf_stats_table[17].base = base.DEC

vr_vrf_stats_table[18] = {}
vr_vrf_stats_table[18].field_name = "vsr_gros"
vr_vrf_stats_table[18].ProtoField = ProtoField.int64
vr_vrf_stats_table[18].base = base.DEC

vr_vrf_stats_table[19] = {}
vr_vrf_stats_table[19].field_name = "vsr_diags"
vr_vrf_stats_table[19].ProtoField = ProtoField.int64
vr_vrf_stats_table[19].base = base.DEC

vr_vrf_stats_table[20] = {}
vr_vrf_stats_table[20].field_name = "vsr_encap_composites"
vr_vrf_stats_table[20].ProtoField = ProtoField.int64
vr_vrf_stats_table[20].base = base.DEC

vr_vrf_stats_table[21] = {}
vr_vrf_stats_table[21].field_name = "vsr_evpn_composites"
vr_vrf_stats_table[21].ProtoField = ProtoField.int64
vr_vrf_stats_table[21].base = base.DEC

vr_vrf_stats_table[22] = {}
vr_vrf_stats_table[22].field_name = "vsr_vrf_translates"
vr_vrf_stats_table[22].ProtoField = ProtoField.int64
vr_vrf_stats_table[22].base = base.DEC

vr_vrf_stats_table[23] = {}
vr_vrf_stats_table[23].field_name = "vsr_vxlan_tunnels"
vr_vrf_stats_table[23].ProtoField = ProtoField.int64
vr_vrf_stats_table[23].base = base.DEC

vr_vrf_stats_table[24] = {}
vr_vrf_stats_table[24].field_name = "vsr_arp_virtual_proxy"
vr_vrf_stats_table[24].ProtoField = ProtoField.int64
vr_vrf_stats_table[24].base = base.DEC

vr_vrf_stats_table[25] = {}
vr_vrf_stats_table[25].field_name = "vsr_arp_virtual_stitch"
vr_vrf_stats_table[25].ProtoField = ProtoField.int64
vr_vrf_stats_table[25].base = base.DEC

vr_vrf_stats_table[26] = {}
vr_vrf_stats_table[26].field_name = "vsr_arp_virtual_flood"
vr_vrf_stats_table[26].ProtoField = ProtoField.int64
vr_vrf_stats_table[26].base = base.DEC

vr_vrf_stats_table[27] = {}
vr_vrf_stats_table[27].field_name = "vsr_arp_physical_stitch"
vr_vrf_stats_table[27].ProtoField = ProtoField.int64
vr_vrf_stats_table[27].base = base.DEC

vr_vrf_stats_table[28] = {}
vr_vrf_stats_table[28].field_name = "vsr_arp_tor_proxy"
vr_vrf_stats_table[28].ProtoField = ProtoField.int64
vr_vrf_stats_table[28].base = base.DEC

vr_vrf_stats_table[29] = {}
vr_vrf_stats_table[29].field_name = "vsr_arp_physical_flood"
vr_vrf_stats_table[29].ProtoField = ProtoField.int64
vr_vrf_stats_table[29].base = base.DEC

vr_vrf_stats_table[30] = {}
vr_vrf_stats_table[30].field_name = "vsr_l2_receives"
vr_vrf_stats_table[30].ProtoField = ProtoField.int64
vr_vrf_stats_table[30].base = base.DEC

vr_vrf_stats_table[31] = {}
vr_vrf_stats_table[31].field_name = "vsr_uuc_floods"
vr_vrf_stats_table[31].ProtoField = ProtoField.int64
vr_vrf_stats_table[31].base = base.DEC

vr_vrf_stats_table[32] = {}
vr_vrf_stats_table[32].field_name = "vsr_pbb_tunnels"
vr_vrf_stats_table[32].ProtoField = ProtoField.int64
vr_vrf_stats_table[32].base = base.DEC

vr_vrf_stats_table[33] = {}
vr_vrf_stats_table[33].field_name = "vsr_udp_mpls_over_mpls_tunnels"
vr_vrf_stats_table[33].ProtoField = ProtoField.int64
vr_vrf_stats_table[33].base = base.DEC
