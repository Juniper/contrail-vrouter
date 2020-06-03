vr_pkt_drop_log_table = {}

vr_pkt_drop_log_table[1] = {}
vr_pkt_drop_log_table[1].field_name = "vr_pkt_drop_log_h_op"
vr_pkt_drop_log_table[1].ProtoField = ProtoField.int8
vr_pkt_drop_log_table[1].base = base.DEC
vr_pkt_drop_log_table[1].append_value = {
             branch = {
                         prepend = ": ",
                         value = function (val) return sandesh_op[val] end
                      },
             subtree = {
                         prepend = ", Operation: ",
                         value = function (val) return sandesh_op[val] end
                       }}
vr_pkt_drop_log_table[1].info_col = {prepend = "Operation: "}
vr_pkt_drop_log_table[1].show_when_zero = true

vr_pkt_drop_log_table[2] = {}
vr_pkt_drop_log_table[2].field_name = "vdl_rid"
vr_pkt_drop_log_table[2].ProtoField = ProtoField.int16
vr_pkt_drop_log_table[2].base = base.DEC

vr_pkt_drop_log_table[3] = {}
vr_pkt_drop_log_table[3].field_name = "vdl_core"
vr_pkt_drop_log_table[3].ProtoField = ProtoField.int16
vr_pkt_drop_log_table[3].base = base.DEC

vr_pkt_drop_log_table[4] = {}
vr_pkt_drop_log_table[4].field_name = "vdl_log_idx"
vr_pkt_drop_log_table[4].ProtoField = ProtoField.int16
vr_pkt_drop_log_table[4].base = base.DEC

vr_pkt_drop_log_table[5] = {}
vr_pkt_drop_log_table[5].field_name = "vdl_max_num_cores"
vr_pkt_drop_log_table[5].ProtoField = ProtoField.int16
vr_pkt_drop_log_table[5].base = base.DEC

vr_pkt_drop_log_table[6] = {}
vr_pkt_drop_log_table[6].field_name = "vdl_pkt_droplog_max_bufsz"
vr_pkt_drop_log_table[6].ProtoField = ProtoField.int16
vr_pkt_drop_log_table[6].base = base.DEC

vr_pkt_drop_log_table[7] = {}
vr_pkt_drop_log_table[7].field_name = "vdl_pkt_droplog_en"
vr_pkt_drop_log_table[7].ProtoField = ProtoField.int16
vr_pkt_drop_log_table[7].base = base.DEC

vr_pkt_drop_log_table[8] = {}
vr_pkt_drop_log_table[8].field_name = "vdl_pkt_droplog_sysctl_en"
vr_pkt_drop_log_table[8].ProtoField = ProtoField.int16
vr_pkt_drop_log_table[8].base = base.DEC

vr_pkt_drop_log_table[9] = {}
vr_pkt_drop_log_table[9].field_name = "vdl_pkt_droplog_arr"
vr_pkt_drop_log_table[9].ProtoField = ProtoField.bytes
vr_pkt_drop_log_table[9].base = base.SPACE
