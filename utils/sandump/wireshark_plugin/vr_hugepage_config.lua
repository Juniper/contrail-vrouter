vr_hugepage_config_table = {}

vr_hugepage_config_table[1] = {}
vr_hugepage_config_table[1].field_name = "vhp_op"
vr_hugepage_config_table[1].ProtoField = ProtoField.int8
vr_hugepage_config_table[1].base = base.DEC
vr_hugepage_config_table[1].append_value = {
              branch = {
                          prepend = ": ",
                          value = function (val) return sandesh_op[val] end
                       },
              subtree = {
                          prepend = ",Operation: ",
                          value = function (val) return sandesh_op[val] end
                        }}
vr_hugepage_config_table[1].info_col = {prepend = "Operation: "}
vr_hugepage_config_table[1].show_when_zero = true

vr_hugepage_config_table[2] = {}
vr_hugepage_config_table[2].field_name = "vhp_mem"
vr_hugepage_config_table[2].ProtoField = ProtoField.bytes
vr_hugepage_config_table[2].base = base.SPACE

vr_hugepage_config_table[3] = {}
vr_hugepage_config_table[3].field_name = "vhp_psize"
vr_hugepage_config_table[3].ProtoField = ProtoField.bytes
vr_hugepage_config_table[3].base = base.SPACE

vr_hugepage_config_table[4] = {}
vr_hugepage_config_table[4].field_name = "vhp_resp"
vr_hugepage_config_table[4].ProtoField = ProtoField.uint32
vr_hugepage_config_table[4].base = base.DEC

vr_hugepage_config_table[5] = {}
vr_hugepage_config_table[5].field_name = "vhp_mem_sz"
vr_hugepage_config_table[5].ProtoField = ProtoField.bytes
vr_hugepage_config_table[5].base = base.SPACE

vr_hugepage_config_table[6] = {}
vr_hugepage_config_table[6].field_name = "vhp_file_paths"
vr_hugepage_config_table[6].ProtoField = ProtoField.bytes
vr_hugepage_config_table[6].base = base.SPACE

vr_hugepage_config_table[7] = {}
vr_hugepage_config_table[7].field_name = "vhp_file_path_sz"
vr_hugepage_config_table[7].ProtoField = ProtoField.bytes
vr_hugepage_config_table[7].base = base.SPACE

