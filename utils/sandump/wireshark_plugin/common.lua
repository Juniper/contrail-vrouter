package.prepend_path("/Applications/Wireshark.app/Contents/PlugIns/wireshark/sandesh_dissector")
require("vr_nexthop");
require("vr_response");
require("vr_interface");
require("vr_flow_table_data");
require("vr_hugepage_config");
require("vr_bridge_table_data");
require("vrouter_ops");
require("vr_vrf");
require("vr_mpls");
require("vr_vrf_stats");
require("vr_drop_stats");
require("vr_route");
require("vr_vxlan");

datatype_size = {}
datatype_size["T_BYTE"] = 1
datatype_size["T_BOOL"] = 1
datatype_size["T_I16"] = 2
datatype_size["T_U16"] = 2
datatype_size["T_I32"] = 4
datatype_size["T_U32"] = 4
datatype_size["T_U64"] = 8
datatype_size["T_I64"] = 8
datatype_size["T_LIST"]  = "variable"
datatype_size["T_STOP"]  = 1
datatype_size["T_STRING"] = "variable"

TType = {}
TType[0] = "T_STOP"
TType[1] = "T_VOID"
TType[2] = "T_BOOL"
TType[3] = "T_BYTE"
TType[4] = "T_DOUBLE"
TType[6] = "T_I16"
TType[8] = "T_I32"
TType[9] = "T_U64"
TType[10] = "T_I64"
TType[11] = "T_STRING"
TType[12] = "T_STRUCT"
TType[13] = "T_MAP"
TType[14] = "T_SET"
TType[15] = "T_LIST"
TType[16] = "T_UTF8"
TType[17] = "T_UTF16"
TType[18] = "T_SANDESH"
TType[19] = "T_U16"
TType[20] = "T_U32"
TType[21] = "T_XML"
TType[22] = "T_IPV4"
TType[23] = "T_UUID"
TType[24] = "T_IPADDR"

sandesh_op = {}
sandesh_op["0"] = "Add"
sandesh_op["1"] = "Get"
sandesh_op["2"] = "Del"
sandesh_op["3"] = "Dump"
sandesh_op["4"] = "Response"
sandesh_op["5"] = "Reset"

flow_op = {}
flow_op["0"] = "Set"
flow_op["1"] = "List"
flow_op["2"] = "Table_get"

family = {}
family["1"] = "Unix"
family["2"] = "Inet"
family["7"] = "Bridge"
family["10"] = "Inet6"

sandesh_global = {}
sandesh_global[1] = {}
sandesh_global[1].name = "vr_response"
sandesh_global[1].table = vr_response_table
sandesh_global[1].abv = "vr_resp"
sandesh_global[1].protocol = "Response"

sandesh_global[2] = {}
sandesh_global[2].name = "vr_nexthop_req"
sandesh_global[2].table = nh_req_table
sandesh_global[2].abv = "nh"
sandesh_global[2].protocol = "Nexthop"
sandesh_global[2].decode_bits = {{nhr_flags, ProtoField.uint32, 0xffffffff}}

sandesh_global[3] = {}
sandesh_global[3].name = "vr_interface_req"
sandesh_global[3].table = vif_req_table
sandesh_global[3].abv = "vif"
sandesh_global[3].protocol = "Vif"
sandesh_global[3].decode_bits = {{vif_flags, ProtoField.uint32, 0xffffffff}, {vif_intf_status_table, ProtoField.uint8, 0xff}}

sandesh_global[4] = {}
sandesh_global[4].name = "vr_flow_table_data"
sandesh_global[4].table = vr_flow_table_data_table
sandesh_global[4].abv = "ftable"
sandesh_global[4].protocol = "Flow Table Data"

sandesh_global[5] = {}
sandesh_global[5].name = "vr_bridge_table_data"
sandesh_global[5].table = vr_bridge_table_data_table
sandesh_global[5].abv = "btable"
sandesh_global[5].protocol = "Bridge Table Data"

sandesh_global[6] = {}
sandesh_global[6].name = "vr_hugepage_config"
sandesh_global[6].table = vr_hugepage_config_table
sandesh_global[6].abv = "vhp"
sandesh_global[6].protocol = "Hugepage Config Table"

sandesh_global[7] = {}
sandesh_global[7].name = "vrouter_ops"
sandesh_global[7].table = vrouter_ops_table
sandesh_global[7].abv = "vo"
sandesh_global[7].protocol = "Vrouter ops"

sandesh_global[8] = {}
sandesh_global[8].name = "vr_vrf_req"
sandesh_global[8].table = vr_vrf_table
sandesh_global[8].abv = "vrf"
sandesh_global[8].protocol = "Vrf"
sandesh_global[8].decode_bits = {{vrf_flags, ProtoField.uint32, 0xffffffff}}

sandesh_global[9] = {}
sandesh_global[9].name = "vr_mpls_req"
sandesh_global[9].table = vr_mpls_table
sandesh_global[9].abv = "mr"
sandesh_global[9].protocol = "Mpls"

sandesh_global[10] = {}
sandesh_global[10].name = "vr_vrf_stats_req"
sandesh_global[10].table = vr_vrf_stats_table
sandesh_global[10].abv = "vsr"
sandesh_global[10].protocol = "Vrf Stats"

sandesh_global[11] = {}
sandesh_global[11].name = "vr_drop_stats_req"
sandesh_global[11].table = vr_drop_stats_table
sandesh_global[11].abv = "vds"
sandesh_global[11].protocol = "Drop Stats"

sandesh_global[12] = {}
sandesh_global[12].name = "vr_route_req"
sandesh_global[12].table = vr_route_table
sandesh_global[12].abv = "rtr" 
sandesh_global[12].protocol = "Route"
sandesh_global[12].decode_bits = {{rtr_label_flags, ProtoField.uint16, 0xffff}}

sandesh_global[13] = {}
sandesh_global[13].name = "vr_vxlan_req"
sandesh_global[13].table = vr_vxlan_table
sandesh_global[13].abv = "vxlanr"
sandesh_global[13].protocol = "Vxlan"
sandesh_global[13].decode_bits = {{rtr_label_flags, ProtoField.uint16, 0xffff}}
