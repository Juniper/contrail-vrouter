# GDB Macros for contrail-vrouter
The gdb-marcos for contrail-vrouter are used to dump the information present in the core file generated from a vrouter code. 

The information dumped includes various interface, next hop, flow and route table details.
# Installation
1. Create a "vrouter_gdb" directory in the "home" directory.
2. Copy all the files to the newly created vrouter_gdb directory.
# Usage
1. Open the vrouter core file using gdb and the binary using the command: "gdb \<binary_file\> \<core_file\>"
2. Source the "vrouter.gdb" gdb-macros file from the vrouter_gdb directory using the command: "source ~/vrouter_gdb/vrouter.gdb"
>Note: The "vrouter.gdb" file internally sources all the other files and hence the other files need not be exclusively sourced.
3. User can use the "help user-defined" command to get the list of user-defined commands callable by the user.
4. The commands "dump\_\<object\>\_all" and "dump\_\<object\>\_index" are called by user to get detailed information about the objects. Here, \<object\> is replaced by "vif", "nh", "flow" or "rtable".
5. The command "help \<user-defined\>" can be used to get a brief description and the Syntax for all callable gdb-marcos.
# Example gdb-macro Calls
1. "dump_vif_all"
2. "dump_vif_index \<vif_id\>"
3. "dump_nh_all"
4. "dump_flow_index \<flow_index\>"
