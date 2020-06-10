#   File: "vrouter.gdb"
#   Debugger sources this file. Make sure the source paths defined
#   below are correct before sourcing this file.

set print pretty
set height 0
source ~/vrouter_gdb/vr_btable.gdb
source ~/vrouter_gdb/vr_vif.gdb
source ~/vrouter_gdb/vr_nexthop.gdb
source ~/vrouter_gdb/vr_flow.gdb
source ~/vrouter_gdb/vr_rtable.gdb
source ~/vrouter_gdb/vr_bridge.gdb
source ~/vrouter_gdb/vr_dpdk.gdb
