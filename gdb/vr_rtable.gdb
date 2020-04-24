#   File: "vr_rtable.gdb"
#   This file contains the gdb macros to dump the route table

define dump_rtable
    set $rtable = (struct ip_mtrie ***)(vn_rtable)
    set $family = $arg1
    if($family == 2)
        printf "vRouter inet4 routing table 0/%d/unicast\n\n", $arg0
    end
    if($family == 10)
        printf "vRouter inet6 routing table 0/%d/unicast\n\n", $arg0
    end
    if($family == 7)
        if(router.vr_bridge_rtable)
            printf "vRouter bridge table 0/%d\n\n", $arg0
            dump_bridge_table router.vr_bridge_rtable.algo_data $arg0
        end
    end
    if($rtable)
        if($family == 2 && $rtable[0][$arg0])
            dump_rtable_ip4 $rtable[0][$arg0].root
        end
        if($family == 10 && $rtable[1][$arg0])
            dump_rtable_ip6 $rtable[1][$arg0].root
        end
    end
end

document dump_rtable
Syntax: dump_rtable vrf_id family(2=inet, 7=bridge, 10=inet6)

end

#No arguments
define rtable_var_init
    set $i0 = 0 
    set $i1 = 0 
    set $i2 = 0 
    set $i3 = 0 
    set $cur_ent0 = (struct ip_bucket_entry *)(0)
    set $cur_ent1 = (struct ip_bucket_entry *)(0)
    set $cur_ent2 = (struct ip_bucket_entry *)(0)    
    set $cur_ent3 = (struct ip_bucket_entry *)(0)
    #$cur_ent4 is dummy, it is never assigned(in ip4)
    set $cur_ent4 = (struct ip_bucket_entry *)(0)
end

#No arguments
define rtable_var_init_ip6
    rtable_var_init
    set $i4 = 0
    set $i5 = 0
    set $i6 = 0
    set $i7 = 0
    set $i8 = 0
    set $i9 = 0
    set $i10 = 0
    set $i11 = 0
    set $i12 = 0
    set $i13 = 0
    set $i14 = 0
    set $i15 = 0
    set $cur_ent5 = (struct ip_bucket_entry *)(0)
    set $cur_ent6 = (struct ip_bucket_entry *)(0)
    set $cur_ent7 = (struct ip_bucket_entry *)(0)
    set $cur_ent8 = (struct ip_bucket_entry *)(0)
    set $cur_ent9 = (struct ip_bucket_entry *)(0)
    set $cur_ent10 = (struct ip_bucket_entry *)(0)
    set $cur_ent11 = (struct ip_bucket_entry *)(0)
    set $cur_ent12 = (struct ip_bucket_entry *)(0)
    set $cur_ent13 = (struct ip_bucket_entry *)(0)
    set $cur_ent14 = (struct ip_bucket_entry *)(0)
    set $cur_ent15 = (struct ip_bucket_entry *)(0)
#$cur_ent16 is dummy, it is never used(in ip6)
    set $cur_ent16 = (struct ip_bucket_entry *)(0)
end

#arg0:rtable[0][vrf_id].root
define dump_rtable_ip4
    rtable_var_init
    set $level = -1
    set $flag = 1
    check_rtable_internal $arg0 $level $flag $cur_ent0
    set $i0 = 1
    while(($i0 < 256) && ($flag == 1))
        set $level = 0
        set $ip_bkt = $cur_ent0[$i0]
        set $i1 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent1
        while(($i1 < 256) && ($flag == 1))
            set $level = 1
            set $ip_bkt = $cur_ent1[$i1]
            set $i2 = 0
            check_rtable_internal $ip_bkt $level $flag $cur_ent2
            while(($i2 < 256) && ($flag == 1))
                set $level = 2
                set $ip_bkt = $cur_ent2[$i2]
                set $i3 = 0
                check_rtable_internal $ip_bkt $level $flag $cur_ent3
                while(($i3 < 256) && ($flag == 1))
                    set $level = 3
                    set $ip_bkt = $cur_ent3[$i3]
                    check_rtable_internal $ip_bkt $level $flag $cur_ent4
                    set $i3 = $i3 + 1
                    set $flag = 1
                end
                set $i2 = $i2 + 1
                set $flag = 1
            end
            set $i1 = $i1 + 1
            set $flag = 1
        end
        set $i0 = $i0 + 1
        set $flag = 1
    end
end

#arg0:rtable[1][vrf_id].root
define dump_rtable_ip6
    rtable_var_init_ip6
    set $level = -1
    set $flag = 1
    check_rtable_internal $arg0 $level $flag $cur_ent0
    set $i0 = 1
    while(($i0 < 256) && ($flag == 1))
        set $level = 0
        set $ip_bkt = $cur_ent0[$i0]
        set $i1 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent1
    while(($i1 < 256) && ($flag == 1))
        set $level = 1
        set $ip_bkt = $cur_ent1[$i1]
        set $i2 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent2
    while(($i2 < 256) && ($flag == 1))
        set $level = 2
        set $ip_bkt = $cur_ent2[$i2]
        set $i3 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent3
    while(($i3 < 256) && ($flag == 1))
        set $level = 3
        set $ip_bkt = $cur_ent3[$i3]
        set $i4 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent4
    while(($i4 < 256) && ($flag == 1))
        set $level = 4
        set $ip_bkt = $cur_ent4[$i4]
        set $i5 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent5
    while(($i5 < 256) && ($flag == 1))
        set $level = 5
        set $ip_bkt = $cur_ent5[$i5]
        set $i6 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent6
    while(($i6 < 256) && ($flag == 1))
        set $level = 6
        set $ip_bkt = $cur_ent6[$i6]
        set $i7 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent7
    while(($i7 < 256) && ($flag == 1))
        set $level = 7
        set $ip_bkt = $cur_ent7[$i7]
        set $i8 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent8
    while(($i8 < 256) && ($flag == 1))
        set $level = 8
        set $ip_bkt = $cur_ent8[$i8]
        set $i9 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent9
    while(($i9 < 256) && ($flag == 1))
        set $level = 9
        set $ip_bkt = $cur_ent9[$i9]
        set $i10 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent10
    while(($i10 < 256) && ($flag == 1))
        set $level = 10
        set $ip_bkt = $cur_ent10[$i10]
        set $i11 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent11
    while(($i11 < 256) && ($flag == 1))
        set $level = 11
        set $ip_bkt = $cur_ent11[$i11]
        set $i12 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent12
    while(($i12 < 256) && ($flag == 1))
        set $level = 12
        set $ip_bkt = $cur_ent12[$i12]
        set $i13 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent13
    while(($i13 < 256) && ($flag == 1))
        set $level = 13
        set $ip_bkt = $cur_ent13[$i13]
        set $i14 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent14
    while(($i14 < 256) && ($flag == 1))
        set $level = 14
        set $ip_bkt = $cur_ent14[$i14]
        set $i15 = 0
        check_rtable_internal $ip_bkt $level $flag $cur_ent15
    while(($i15 < 256) && ($flag == 1))
        set $level = 15
        set $ip_bkt = $cur_ent15[$i15]
        check_rtable_internal $ip_bkt $level $flag $cur_ent16
        set $i15 = $i15 + 1
        set $flag = 1
    end
    set $i14 = $i14 + 1
    set $flag = 1
    end
    set $i13 = $i13 + 1
    set $flag = 1
    end
    set $i12 = $i12 + 1
    set $flag = 1
    end
    set $i11 = $i11 + 1
    set $flag = 1
    end
    set $i10 = $i10 + 1
    set $flag = 1
    end
    set $i9 = $i9 + 1
    set $flag = 1
    end
    set $i8 = $i8 + 1
    set $flag = 1
    end
    set $i7 = $i7 + 1
    set $flag = 1
    end
    set $i6 = $i6 + 1
    set $flag = 1
    end
    set $i5 = $i5 + 1
    set $flag = 1
    end
    set $i4 = $i4 + 1
    set $flag = 1
    end
    set $i3 = $i3 + 1
    set $flag = 1
    end
    set $i2 = $i2 + 1
    set $flag = 1
    end
    set $i1 = $i1 + 1
    set $flag = 1
    end
    set $i0 = $i0 + 1
    set $flag = 1
    end

end


#arg0:ip_bkt, arg1:level, arg2:flag, $cur_ent(0,1,2,3)
define check_rtable_internal
    if($arg0.entry_type == 1)
#bucket: go to next level
        if($arg0.entry_data.bucket_p)
            set $arg3 = (struct ip_bucket_entry *)($arg0.entry_data.bucket_p.bkt_data)
        else
            printf "Unexpected Null bucket pointer at "
            if($family == 2)
                printf "%d.%d.%d.%d", $i0, $i1, $i2, $i3
            end
            if($family == 10)
                printf "%x%02x:%x%02x:%x%02x:%x%02x:",$i0,$i1,$i2,$i3,$i4,$i5,$i6,$i7
                printf "%x%02x:%x%02x:%x%02x:%x%02x",$i8,$i9,$i10,$i11,$i12,$i13,$i14,$i15
            end
            print_p_len $arg1
            printf "\n"
            set $arg2 = 0
        end
    end

    if($arg0.entry_type == 2)
#nexthop: change presets and print rtable entry
        set $arg2 = 0
        if($arg0.entry_data.nexthop_p)
            print_rtable_entry $arg0 $arg1
        else
            printf "Unexpected Null Nexthop pointer at "
            if($family == 2)
                printf "%d.%d.%d.%d", $i0, $i1, $i2, $i3
            end
            if($family == 10)
                printf "%x%02x:%x%02x:%x%02x:%x%02x:",$i0,$i1,$i2,$i3,$i4,$i5,$i6,$i7
                printf "%x%02x:%x%02x:%x%02x:%x%02x",$i8,$i9,$i10,$i11,$i12,$i13,$i14,$i15
            end
            print_p_len $arg1
            printf "\n"
        end
    end
end

#arg0:ip_bkt, arg1:level
define print_rtable_entry
    if($family == 2)
        printf "%d.%d.%d.%d", $i0, $i1, $i2, $i3
    else
        printf "%x%02x:%x%02x:%x%02x:%x%02x:",$i0,$i1,$i2,$i3,$i4,$i5,$i6,$i7
        printf "%x%02x:%x%02x:%x%02x:%x%02x",$i8,$i9,$i10,$i11,$i12,$i13,$i14,$i15
    end
    print_p_len $arg1
    printf "   PPL:%u   ", $arg0.entry_prefix_len
    print_rtable_flag $arg0.entry_label_flags
    set $label_val = -1
    if($arg0.entry_label_flags & 1)
        set $label_val = $arg0.entry_label
    end
    printf "   Label:%d   nh:%u", $label_val, $arg0.entry_data.nexthop_p.nh_id
#MAC id using Bridge index here. The Bridge Index is temporary
    printf "   Bridge(Id):"
    if($arg0.entry_bridge_index != -1)
        get_bridge_mac $arg0.entry_bridge_index
        printf "(%d)\n", $arg0.entry_bridge_index
    else
        printf "%d\n", $arg0.entry_bridge_index
    end
end
define print_p_len
    set $p_len = ($arg0 + 1)*8
    printf "/%d", $p_len
end

#arg0:entry_label_flags
define print_rtable_flag
    set $flag_mask = 1
    printf "Flags:"
    if($arg0 & $flag_mask)
        printf "L"
    end
    set $flag_mask = $flag_mask << 1
    if($arg0 & $flag_mask)
        printf "P"
    end
    set $flag_mask = $flag_mask << 1
    if($arg0 & $flag_mask)
        printf "T"
    end
    set $flag_mask = $flag_mask << 1
    if($arg0 & $flag_mask)
        printf "F"
    end
end

#arg0:bridge_index
define get_bridge_mac
    set $bridge_tab = (struct vr_htable *)(router.vr_bridge_rtable.algo_data)
    set $bridge_addr = -1
    if($arg0 < $bridge_tab.ht_hentries)
        get_index_addr_btable $bridge_tab.ht_htable $arg0 $bridge_addr
    else
        get_index_addr_btable $bridge_tab.ht_otable $arg0 $bridge_addr
    end
    set $cur_bridge = (struct vr_bridge_entry *)($bridge_addr)
    mac_address $cur_bridge.be_key.be_mac
end


