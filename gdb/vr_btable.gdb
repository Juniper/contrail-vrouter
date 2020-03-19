#	File: "vr_btable.gdb"
#	This file contains the gdb macro to get the resolved btable
#	address for any field stored as a struct btable entry.



#Args in order: Pointer to required Btable, index value, return Address
define get_index_addr_btable
	set $bt_ret_val = -1
	set $table = (struct vr_btable *)($arg0)
	if($arg1 < $table.vb_entries)
        set $entry_cont = $arg1 * $table.vb_esize
        set $t_index = (int)($entry_cont / ($table.vb_alloc_limit))
        set $t_offset  = $entry_cont % ($table.vb_alloc_limit)
        set $bt_ret_val = ($table.vb_mem[$t_index]) + $t_offset
        set $arg2 = $bt_ret_val
	end
end

document get_index_addr_btable
Syntax: get_index_addr_btable pointerToBtable Index returnAddr
Return Value: $bt_rel_val(Generic Ptr) which holds address of required struct

end
