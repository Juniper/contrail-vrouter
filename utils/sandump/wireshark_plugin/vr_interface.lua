vif_type = {}
vif_type["0"] = "Host"
vif_type["1"] = "Agent"
vif_type["2"] = "Physical"
vif_type["3"] = "Virtual"
vif_type["4"] = "Xen ll host"
vif_type["5"] = "Gateway"
vif_type["6"] = "Virtual Vlan"
vif_type["7"] = "Stats"
vif_type["8"] = "Vlan"
vif_type["9"] = "Monitoring"
vif_type["10"] = "Max"

vif_transport = {}
vif_transport["0"] = "Virtual"
vif_transport["1"] = "Eth"
vif_transport["2"] = "Pmd"
vif_transport["3"] = "Socket"

vif_flags = {}
vif_flags["0x00000001"] = "VIF_FLAG_POLICY_ENABLED"
vif_flags["0x00000002"] = "VIF_FLAG_XCONNECT"
vif_flags["0x00000004"] = "VIF_FLAG_SERVICE_IF"
vif_flags["0x00000008"] = "VIF_FLAG_MIRROR_RX"
vif_flags["0x00000010"] = "VIF_FLAG_MIRROR_TX"
vif_flags["0x00000020"] = "VIF_FLAG_TX_CSUM_OFFLOAD"
vif_flags["0x00000040"] = "VIF_FLAG_L3_ENABLED"
vif_flags["0x00000080"] = "VIF_FLAG_L2_ENABLED"
vif_flags["0x00000100"] = "VIF_FLAG_DHCP_ENABLED"
vif_flags["0x00000200"] = "VIF_FLAG_VHOST_PHYS"
vif_flags["0x00000400"] = "VIF_FLAG_PROMISCOUS"
vif_flags["0x00000800"] = "VIF_FLAG_NATIVE_VLAN_TAG"
vif_flags["0x00001000"] = "VIF_FLAG_NO_ARP_PROXY"
vif_flags["0x00002000"] = "VIF_FLAG_PMD"
vif_flags["0x00004000"] = "VIF_FLAG_FILTERING_OFFLOAD"
vif_flags["0x00008000"] = "VIF_FLAG_MONITORED"
vif_flags["0x00010000"] = "VIF_FLAG_UNKNOWN_UC_FLOOD"
vif_flags["0x00020000"] = "VIF_FLAG_VLAN_OFFLOAD"
vif_flags["0x00040000"] = "VIF_FLAG_DROP_NEW_FLOWS"
vif_flags["0x00080000"] = "VIF_FLAG_MAC_LEARN"
vif_flags["0x00100000"] = "VIF_FLAG_MAC_PROXY"
vif_flags["0x00200000"] = "VIF_FLAG_ETREE_ROOT"
vif_flags["0x00400000"] = "VIF_FLAG_GRO_NEEDED"
vif_flags["0x00800000"] = "VIF_FLAG_MRG_RXBUF"
vif_flags["0x01000000"] = "VIF_FLAG_MIRROR_NOTAG"
vif_flags["0x02000000"] = "VIF_FLAG_IGMP_ENABLED"
vif_flags["0x04000000"] = "VIF_FLAG_MOCK_PHYSICAL"
vif_flags["0x08000000"] = "VIF_FLAG_HBS_LEFT"
vif_flags["0x10000000"] = "VIF_FLAG_HBS_RIGHT"

vif_intf_status_table = {}
vif_intf_status_table["0x01"] = "Master"
vif_intf_status_table["0x02"] = "Slave0"
vif_intf_status_table["0x04"] = "Slave1"
vif_intf_status_table["0x08"] = "Slave2"
vif_intf_status_table["0x10"] = "Slave3"
vif_intf_status_table["0x20"] = "Slave4"
vif_intf_status_table["0x40"] = "Slave5"


vif_req_table = {}

vif_req_table[1] = {}
vif_req_table[1].field_name = "vifr_h_op"
vif_req_table[1].ProtoField = ProtoField.int8
vif_req_table[1].base = base.DEC
vif_req_table[1].append_value = {
             branch = {
                          prepend = ": ",
                          value = function (val) return sandesh_op[val] end
                      }}
vif_req_table[1].info_col = {prepend = "Operation: "}
vif_req_table[1].show_when_zero = true

vif_req_table[2] = {}
vif_req_table[2].field_name = "vifr_core"
vif_req_table[2].ProtoField = ProtoField.uint32
vif_req_table[2].base = base.DEC
vif_req_table[2].default = {buffer = "ffffffff", display= -1}

vif_req_table[3] = {}
vif_req_table[3].field_name = "vifr_type"
vif_req_table[3].ProtoField = ProtoField.int32
vif_req_table[3].base = base.DEC
vif_req_table[3].append_value = {
             branch = {
                         prepend = ": ",
                         value = function (val) return vif_type[val] end
                      },
             subtree = {
                         prepend = ", Type: ",
                         value = function (val) return vif_type[val] end
                       }}
vif_req_table[3].info_col = {prepend = " Type: "}
vif_req_table[3].show_when_zero = true

vif_req_table[4] = {}
vif_req_table[4].field_name = "vifr_flags"
vif_req_table[4].ProtoField = ProtoField.uint32
vif_req_table[4].base = base.HEX
vif_req_table[4].decode_bits = vif_flags

vif_req_table[5] = {}
vif_req_table[5].field_name = "vifr_vrf"
vif_req_table[5].ProtoField = ProtoField.int32
vif_req_table[5].base = base.DEC
vif_req_table[5].show_when_zero = true

vif_req_table[6] = {}
vif_req_table[6].field_name = "vifr_idx"
vif_req_table[6].ProtoField = ProtoField.int32
vif_req_table[6].base = base.DEC
vif_req_table[6].append_value = {
           subtree = {
                         prepend = ", ID: ",
                         value = function (val) return val end
                     }}
vif_req_table[6].info_col = {prepend = " ID: "}
vif_req_table[6].show_when_zero = true

vif_req_table[7] = {}
vif_req_table[7].field_name = "vifr_rid"
vif_req_table[7].ProtoField = ProtoField.int32
vif_req_table[7].base = base.DEC

vif_req_table[8] = {}
vif_req_table[8].field_name = "vifr_os_idx"
vif_req_table[8].ProtoField = ProtoField.int32
vif_req_table[8].base = base.DEC

vif_req_table[9] = {}
vif_req_table[9].field_name = "vifr_mtu"
vif_req_table[9].ProtoField = ProtoField.int32
vif_req_table[9].base = base.DEC

vif_req_table[10] = {}
vif_req_table[10].field_name = "vifr_name"
vif_req_table[10].ProtoField = ProtoField.string
vif_req_table[10].append_value = {
           subtree = {
                        prepend = ", Name: ",
                        value = function (val) return val end
                     }}
vif_req_table[10].info_col = {prepend = " Name: "}

vif_req_table[11] = {}
vif_req_table[11].field_name = "vifr_ibytes"
vif_req_table[11].ProtoField = ProtoField.int64
vif_req_table[11].base = base.DEC

vif_req_table[12] = {}
vif_req_table[12].field_name = "vifr_ipackets"
vif_req_table[12].ProtoField = ProtoField.int64
vif_req_table[12].base = base.DEC

vif_req_table[13] = {}
vif_req_table[13].field_name = "vifr_ierrors"
vif_req_table[13].ProtoField = ProtoField.int64
vif_req_table[13].base = base.DEC

vif_req_table[14] = {}
vif_req_table[14].field_name = "vifr_obytes"
vif_req_table[14].ProtoField = ProtoField.int64
vif_req_table[14].base = base.DEC

vif_req_table[15] = {}
vif_req_table[15].field_name = "vifr_opackets"
vif_req_table[15].ProtoField = ProtoField.int64
vif_req_table[15].base = base.DEC

vif_req_table[16] = {}
vif_req_table[16].field_name = "vifr_oerrors"
vif_req_table[16].ProtoField = ProtoField.int64
vif_req_table[16].base = base.DEC

vif_req_table[17] = {}
vif_req_table[17].field_name = "vifr_queue_ipackets"
vif_req_table[17].ProtoField = ProtoField.int64
vif_req_table[17].base = base.DEC

vif_req_table[18] = {}
vif_req_table[18].field_name = "vifr_queue_ierrors"
vif_req_table[18].ProtoField = ProtoField.int64
vif_req_table[18].base = base.DEC

vif_req_table[19] = {}
vif_req_table[19].field_name = "vifr_queue_ierrors_to_lcore"
vif_req_table[19].ProtoField = ProtoField.bytes
vif_req_table[19].base = base.SPACE

vif_req_table[20] = {}
vif_req_table[20].field_name = "vifr_queue_opackets"
vif_req_table[20].ProtoField = ProtoField.int64
vif_req_table[20].base = base.DEC

vif_req_table[21] = {}
vif_req_table[21].field_name = "vifr_queue_oerrors"
vif_req_table[21].ProtoField = ProtoField.int64
vif_req_table[21].base = base.DEC

vif_req_table[22] = {}
vif_req_table[22].field_name = "vifr_port_ipackets"
vif_req_table[22].ProtoField = ProtoField.int64
vif_req_table[22].base = base.DEC

vif_req_table[23] = {}
vif_req_table[23].field_name = "vifr_port_ierrors"
vif_req_table[23].ProtoField = ProtoField.int64
vif_req_table[23].base = base.DEC

vif_req_table[24] = {}
vif_req_table[24].field_name = "vifr_port_isyscalls"
vif_req_table[24].ProtoField = ProtoField.int64
vif_req_table[24].base = base.DEC

vif_req_table[25] = {}
vif_req_table[25].field_name = "vifr_port_inombufs"
vif_req_table[25].ProtoField = ProtoField.int64
vif_req_table[25].base = base.DEC

vif_req_table[26] = {}
vif_req_table[26].field_name = "vifr_port_opackets"
vif_req_table[26].ProtoField = ProtoField.int64
vif_req_table[26].base = base.DEC

vif_req_table[27] = {}
vif_req_table[27].field_name = "vifr_port_oerrors"
vif_req_table[27].ProtoField = ProtoField.int64
vif_req_table[27].base = base.DEC

vif_req_table[28] = {}
vif_req_table[28].field_name = "vifr_port_osyscalls"
vif_req_table[28].ProtoField = ProtoField.int64
vif_req_table[28].base = base.DEC

vif_req_table[29] = {}
vif_req_table[29].field_name = "vifr_dev_ibytes"
vif_req_table[29].ProtoField = ProtoField.int64
vif_req_table[29].base = base.DEC

vif_req_table[30] = {}
vif_req_table[30].field_name = "vifr_dev_ipackets"
vif_req_table[30].ProtoField = ProtoField.int64
vif_req_table[30].base = base.DEC

vif_req_table[31] = {}
vif_req_table[31].field_name = "vifr_dev_ierrors"
vif_req_table[31].ProtoField = ProtoField.int64
vif_req_table[31].base = base.DEC

vif_req_table[32] = {}
vif_req_table[32].field_name = "vifr_dev_inombufs"
vif_req_table[32].ProtoField = ProtoField.int64
vif_req_table[32].base = base.DEC

vif_req_table[33] = {}
vif_req_table[33].field_name = "vifr_dev_obytes"
vif_req_table[33].ProtoField = ProtoField.int64
vif_req_table[33].base = base.DEC

vif_req_table[34] = {}
vif_req_table[34].field_name = "vifr_dev_opackets"
vif_req_table[34].ProtoField = ProtoField.int64
vif_req_table[34].base = base.DEC

vif_req_table[35] = {}
vif_req_table[35].field_name = "vifr_dev_oerrors"
vif_req_table[35].ProtoField = ProtoField.int64
vif_req_table[35].base = base.DEC

vif_req_table[36] = {}
vif_req_table[36].field_name = "vifr_ref_cnt"
vif_req_table[36].ProtoField = ProtoField.int32
vif_req_table[36].base = base.DEC

vif_req_table[37] = {}
vif_req_table[37].field_name = "vifr_marker"
vif_req_table[37].ProtoField = ProtoField.int32
vif_req_table[37].base = base.DEC

vif_req_table[38] = {}
vif_req_table[38].field_name = "vifr_mac"
vif_req_table[38].ProtoField = ProtoField.bytes
vif_req_table[38].base = base.COLON

vif_req_table[39] = {}
vif_req_table[39].field_name = "vifr_ip"
vif_req_table[39].ProtoField = ProtoField.ipv4

vif_req_table[40] = {}
vif_req_table[40].field_name = "vifr_ip6_u"
vif_req_table[40].ProtoField = ProtoField.bytes
vif_req_table[40].base = base.COLON

vif_req_table[41] = {}
vif_req_table[41].field_name = "vifr_ip6_l"
vif_req_table[41].ProtoField = ProtoField.bytes
vif_req_table[41].base = base.COLON

vif_req_table[42] = {}
vif_req_table[42].field_name = "vifr_context"
vif_req_table[42].ProtoField = ProtoField.int32
vif_req_table[42].base = base.DEC

vif_req_table[43] = {}
vif_req_table[43].field_name = "vifr_mir_id"
vif_req_table[43].ProtoField = ProtoField.int16
vif_req_table[43].base = base.DEC

vif_req_table[44] = {}
vif_req_table[44].field_name = "vifr_speed"
vif_req_table[44].ProtoField = ProtoField.int32
vif_req_table[44].base = base.DEC

vif_req_table[45] = {}
vif_req_table[45].field_name = "vifr_duplex"
vif_req_table[45].ProtoField = ProtoField.int32
vif_req_table[45].base = base.DEC

vif_req_table[46] = {}
vif_req_table[46].field_name = "vifr_vlan_id"
vif_req_table[46].ProtoField = ProtoField.int16
vif_req_table[46].base = base.DEC

vif_req_table[47] = {}
vif_req_table[47].field_name = "vifr_parent_vif_idx"
vif_req_table[47].ProtoField = ProtoField.int32
vif_req_table[47].base = base.DEC

vif_req_table[48] = {}
vif_req_table[48].field_name = "vifr_nh_id"
vif_req_table[48].ProtoField = ProtoField.int32
vif_req_table[48].base = base.DEC

vif_req_table[49] = {}
vif_req_table[49].field_name = "vifr_cross_connect_idx"
vif_req_table[49].ProtoField = ProtoField.int32
vif_req_table[49].base = base.DEC

vif_req_table[50] = {}
vif_req_table[50].field_name = "vifr_src_mac"
vif_req_table[50].ProtoField = ProtoField.bytes
vif_req_table[50].base = base.COLON

vif_req_table[51] = {}
vif_req_table[51].field_name = "vifr_bridge_idx"
vif_req_table[51].ProtoField = ProtoField.bytes
vif_req_table[51].base = base.SPACE

vif_req_table[52] = {}
vif_req_table[52].field_name = "vifr_ovlan_id"
vif_req_table[52].ProtoField = ProtoField.int16
vif_req_table[52].base = base.DEC

vif_req_table[53] = {}
vif_req_table[53].field_name = "vifr_transport"
vif_req_table[53].ProtoField = ProtoField.int8
vif_req_table[53].base = base.DEC
vif_req_table[53].append_value = {
          branch = {
                      prepend = ": ",
                      value = function (val) return vif_transport[val] end
                   }}
vif_req_table[53].show_when_zero = true

vif_req_table[54] = {}
vif_req_table[54].field_name = "vifr_fat_flow_protocol_port"
vif_req_table[54].ProtoField = ProtoField.bytes
vif_req_table[54].base = base.SPACE

vif_req_table[55] = {}
vif_req_table[55].field_name = "vifr_qos_map_index"
vif_req_table[55].ProtoField = ProtoField.int16
vif_req_table[55].base = base.DEC

vif_req_table[56] = {}
vif_req_table[56].field_name = "vifr_in_mirror_md"
vif_req_table[56].ProtoField = ProtoField.bytes
vif_req_table[56].base = base.SPACE

vif_req_table[57] = {}
vif_req_table[57].field_name = "vifr_out_mirror_md"
vif_req_table[57].ProtoField = ProtoField.bytes
vif_req_table[57].base = base.SPACE

vif_req_table[58] = {}
vif_req_table[58].field_name = "vifr_dpackets"
vif_req_table[58].ProtoField = ProtoField.uint64
vif_req_table[58].base = base.DEC

vif_req_table[59] = {}
vif_req_table[59].field_name = "vifr_hw_queues"
vif_req_table[59].ProtoField = ProtoField.bytes
vif_req_table[59].base = base.SPACE

vif_req_table[60] = {}
vif_req_table[60].field_name = "vifr_isid"
vif_req_table[60].ProtoField = ProtoField.uint32
vif_req_table[60].base = base.DEC

vif_req_table[61] = {}
vif_req_table[61].field_name = "vifr_pbb_mac"
vif_req_table[61].ProtoField = ProtoField.bytes
vif_req_table[61].base = base.COLON

vif_req_table[62] = {}
vif_req_table[62].field_name = "vifr_vhostuser_mode"
vif_req_table[62].ProtoField = ProtoField.int8
vif_req_table[62].base = base.DEC

vif_req_table[63] = {}
vif_req_table[63].field_name = "vifr_mcast_vrf"
vif_req_table[63].ProtoField = ProtoField.int32
vif_req_table[63].base = base.DEC

vif_req_table[64] = {}
vif_req_table[64].field_name = "vifr_if_guid"
vif_req_table[64].ProtoField = ProtoField.bytes
vif_req_table[64].base = base.SPACE

vif_req_table[65] = {}
vif_req_table[65].field_name = "vifr_fat_flow_exclude_ip_list"
vif_req_table[65].ProtoField = ProtoField.ipv4

vif_req_table[66] = {}
vif_req_table[66].field_name = "vifr_fat_flow_exclude_ip6_u_list"
vif_req_table[66].ProtoField = ProtoField.bytes
vif_req_table[66].base = base.COLON

vif_req_table[67] = {}
vif_req_table[67].field_name = "vifr_fat_flow_exclude_ip6_l_list"
vif_req_table[67].ProtoField = ProtoField.bytes
vif_req_table[67].base = base.COLON

vif_req_table[68] = {}
vif_req_table[68].field_name = "vifr_fat_flow_exclude_ip6_plen_list"
vif_req_table[68].ProtoField = ProtoField.ipv6

vif_req_table[77] = {}
vif_req_table[77].field_name = "vifr_fat_flow_src_prefix_h"
vif_req_table[77].ProtoField = ProtoField.bytes
vif_req_table[77].base = base.SPACE

vif_req_table[78] = {}
vif_req_table[78].field_name = "vifr_fat_flow_src_prefix_l"
vif_req_table[78].ProtoField = ProtoField.bytes
vif_req_table[78].base = base.SPACE

vif_req_table[79] = {}
vif_req_table[79].field_name = "vifr_fat_flow_src_prefix_mask"
vif_req_table[79].ProtoField = ProtoField.bytes
vif_req_table[79].base = base.SPACE

vif_req_table[80] = {}
vif_req_table[80].field_name = "vifr_fat_flow_src_aggregate_plen"
vif_req_table[80].ProtoField = ProtoField.bytes
vif_req_table[80].base = base.SPACE

vif_req_table[81] = {}
vif_req_table[81].field_name = "vifr_fat_flow_dst_prefix_h"
vif_req_table[81].ProtoField = ProtoField.bytes
vif_req_table[81].base = base.SPACE

vif_req_table[82] = {}
vif_req_table[82].field_name = "vifr_fat_flow_dst_prefix_l"
vif_req_table[82].ProtoField = ProtoField.bytes
vif_req_table[82].base = base.SPACE

vif_req_table[83] = {}
vif_req_table[83].field_name = "vifr_fat_flow_dst_prefix_mask"
vif_req_table[83].ProtoField = ProtoField.bytes
vif_req_table[83].base = base.SPACE

vif_req_table[84] = {}
vif_req_table[84].field_name = "vifr_fat_flow_dst_aggregate_plen"
vif_req_table[84].ProtoField = ProtoField.bytes
vif_req_table[84].base = base.SPACE

vif_req_table[85] = {}
vif_req_table[85].field_name = "vifr_intf_status"
vif_req_table[85].ProtoField = ProtoField.uint8
vif_req_table[85].base = base.HEX
vif_req_table[85].decode_bits  = vif_intf_status_table

vif_req_table[86] = {}
vif_req_table[86].field_name = "vifr_fab_name"
vif_req_table[86].ProtoField = ProtoField.bytes
vif_req_table[86].base = base.SPACE

vif_req_table[87] = {}
vif_req_table[87].field_name = "vifr_fab_drv_name"
vif_req_table[87].ProtoField = ProtoField.bytes
vif_req_table[87].base = base.SPACE

vif_req_table[88] = {}
vif_req_table[88].field_name = "vifr_num_bond_slave"
vif_req_table[88].ProtoField = ProtoField.int8
vif_req_table[88].base = base.DEC

vif_req_table[89] = {}
vif_req_table[89].field_name = "vifr_bond_slave_name"
vif_req_table[89].ProtoField = ProtoField.bytes
vif_req_table[89].base = base.SPACE

vif_req_table[90] = {}
vif_req_table[90].field_name = "vifr_bond_slave_drv_name"
vif_req_table[90].ProtoField = ProtoField.bytes
vif_req_table[90].base = base.SPACE

vif_req_table[91] = {}
vif_req_table[91].field_name = "vifr_vlan_tag"
vif_req_table[91].ProtoField = ProtoField.uint32
vif_req_table[91].base = base.DEC

vif_req_table[92] = {}
vif_req_table[92].field_name = "vifr_vlan_name"
vif_req_table[92].ProtoField = ProtoField.bytes
vif_req_table[92].base = base.SPACE



