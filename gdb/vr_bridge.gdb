#   File: "vr_bridge.gdb"
#   This file contains the gdb macros to dump the vrouter bridge table.

#arg0:bridge_table, arg1:vrf_id
define dump_bridge_table
    set $bridge_flag = 0
    set $bridge_table = (struct vr_htable *)($arg0)
    set $i = 0
    set $j = 0
    set $temp_table_ptr = -1
    if($bridge_table)
        get_index_addr_btable $bridge_table.ht_htable $i $temp_table_ptr
        if($bridge_table.ht_used_entries)
        while($i < $bridge_table.ht_hentries)
            dump_bridge_internal $temp_table_ptr $i $arg1
            set $i = $i + 1
            set $temp_table_ptr = $temp_table_ptr + $bridge_table.ht_entry_size
        end
        end
        get_index_addr_btable $bridge_table.ht_otable $j $temp_table_ptr
        if($bridge_table.ht_used_oentries)
        while($j < $bridge_table.ht_oentries)
            dump_bridge_internal $temp_table_ptr $j $arg1
            set $j = $j + 1
            set $temp_table_ptr = $temp_table_ptr + $bridge_table.ht_entry_size
        end
        end
    end
end

#arg0:start_index, arg1:end_index
define dump_bridge_range
    set $bridge_flag = 1
    set $bridge_table = (struct vr_htable *)(router.vr_bridge_rtable.algo_data)
    set $temp_table_ptr = -1
    set $i = $arg0
    set $j = 0
    set $k = 0
    set $temp_vrf = -1
    if($bridge_table)
        if($arg1>$bridge_table.ht_hentries)
            set $k = $arg1 - $bridge_table.ht_hentries
        end
        get_index_addr_btable $bridge_table.ht_htable $i $temp_table_ptr
        if($bridge_table.ht_used_entries)
        while(($i < $bridge_table.ht_hentries) && ($i<$arg1))
            dump_bridge_internal $temp_table_ptr $i $temp_vrf
            set $i = $i + 1
            set $temp_table_ptr = $temp_table_ptr + $bridge_table.ht_entry_size
        end
        end
        get_index_addr_btable $bridge_table.ht_otable $j $temp_table_ptr
        if(($bridge_table.ht_used_oentries) && ($k))
        while(($j<$bridge_table.ht_oentries) && ($j<$k))
            dump_bridge_internal $temp_table_ptr $j $temp_vrf
            set $j = $j + 1
            set $temp_table_ptr = $temp_table_ptr + $bridge_table.ht_entry_size
        end
        end
    end
end

document dump_bridge_range
Syntax:dump_bridge_range start_index end_index
This function prints valid bridge entries in the range start_id to end_id

end

#arg0:bridge index
define dump_bridge_index
    set $bridge_table = (struct vr_htable *)(router.vr_bridge_rtable.algo_data)
    if($bridge_table != 0)
        set $cur_bridge_addr = -1
        if($arg0 < $bridge_table.ht_hentries)
            get_index_addr_btable $bridge_table.ht_htable $arg0 $cur_bridge_addr
        else
            if($arg0 < $bridge_table.ht_oentries)
                get_index_addr_btable $bridge_table.ht_otable $arg0 $cur_bridge_addr
            end
        end
        if($cur_bridge_addr != -1)
            set $temp_vrf = -1
            set $bridge_flag = 1
            dump_bridge_internal $cur_bridge_addr $arg0 $temp_vrf
            if(!($cur_bridge.be_flags & 1))
                printf "Bridge %d is null or invalid\n", $arg0
            end
        end
    else
        printf "Null Bridge Table\n"
    end
end

document dump_bridge_index
Syantax:dump_bridge_index bridge_index
This function dumps bridge with index = bridge_index

end

#($cur_bridge.be_key.be_vrf_id == $arg2)
#arg0:bridge_table_ptr, arg1:index, arg2:vrfid
define dump_bridge_internal
#    set $cur_bridge_addr = -1
#    get_index_addr_btable $arg0 $arg1 $cur_bridge_addr
    if($arg0 != -1)
        set $cur_bridge = (struct vr_bridge_entry *)($arg0)
        if(($cur_bridge.be_flags & 1)&&(($cur_bridge.be_key.be_vrf_id == $arg2)||$bridge_flag))
            printf "Idx:%-9dDstMac:", $cur_bridge.be_hentry.hentry_index
            mac_address $cur_bridge.be_key.be_mac
            printf "   Label:%-7dnh:%-7d",$cur_bridge.be_label,$cur_bridge.be_nh_id
            printf "Stats:%-9lu", $cur_bridge.be_packets
            print_bridge_flags $cur_bridge.be_flags
            printf "\n"
        else
            if(($arg1+1) % 1000 == 0)
                printf "Loading id:%d\n", $arg1 + 1
            end
        end
    end
end

#arg0:be_flags
define print_bridge_flags
    printf "Flags:"
    set $flag_mask = 1
    if($arg0 & $flag_mask)
#validity check only. Always true, No printing required.
        printf ""
    end
    set $flag_mask = $flag_mask << 1
    if($arg0 & $flag_mask)
        printf "L"
    end
    set $flag_mask = $flag_mask << 1
    if($arg0 & $flag_mask)
        printf "Df"
    end
    set $flag_mask = $flag_mask << 1
    if($arg0 & $flag_mask)
        printf "Mm"
    end
    set $flag_mask = $flag_mask << 1
    if($arg0 & $flag_mask)
        printf "L2c"
    end
    set $flag_mask = $flag_mask << 1
    if($arg0 & $flag_mask)
        printf "N"
    end
    set $flag_mask = $flag_mask << 1
    if($arg0 & $flag_mask)
        printf "Ec"
    end
end
