#	File: "vr_nexthop.gdb"
#	This file contains the gdb macros to dump the vrouter nexthop information.


define dump_nh_all
	if(router)
        printf "\nVRouter Nexthop Table\n\n"
        set $r1 = router
        set $i = 0
        if($r1.vr_nexthops)
    		while($i<$r1.vr_max_nexthops)
                dump_nh_index $i
                set $i = $i + 1
            end
        end
	end
end

document dump_nh_all
Displays all available Nexthops in sequence
Number of arguments: 0
end

define dump_nh_index
	set $cur_nh_addr = -1
	get_index_addr_btable router.vr_nexthops $arg0 $cur_nh_addr
	if($cur_nh_addr != -1)
        set $cur_nh = *(struct vr_nexthop **)($cur_nh_addr)
        if($cur_nh != 0)
            printf "ID:%-9dType:", $arg0
            print_nh_type $cur_nh.nh_type
            printf " Fmly:"
            print_nh_family $cur_nh.nh_family
            printf " Users:%u Rid:%u ", $cur_nh.nh_users, $cur_nh.nh_rid
            printf "Vrf:%d", $cur_nh.nh_vrf
            printf "\n            Router:0x%x ", $cur_nh.nh_router
            print_nh_flags $cur_nh.nh_flags
            if ($cur_nh.nh_dev || $cur_nh.nh_crypt_dev)
                printf "\n            "
            end
            if ($cur_nh.nh_dev)
                printf "DevVifID:%u ", $cur_nh.nh_dev.vif_idx
            end
            if ($cur_nh.nh_crypt_dev)
                printf "CryptDevVifID:%u ", $cur_nh.nh_crypt_dev.vif_idx
            end
            get_union_type $cur_nh.nh_type $cur_nh.nh_family $cur_nh.nh_flags $cur_nh.nh_u
            if($cur_nh.nh_data_size)
                printf "\n            Data:"
                set $temp_count = 0
                while($temp_count <14)
                    printf "%02x ", $cur_nh.nh_data[$temp_count++]
                end
            end
            printf "\n\n"
        end
	end
end

document dump_nh_index
Syntax: dump_nh_index nhid
Displays details about an element of type vr_nexthop with id: nhid
end

#arg0: nh_type of cur_nh
define print_nh_type
	if($arg0 == 0)
    	printf "Dead"
    end
    if($arg0 == 1)
    	printf "Receive"
    end
    if($arg0 == 2)
     	printf "Encap"
    end
    if($arg0 == 3)
    	printf "Tunnel"
    end
    if($arg0 == 4)
        printf "Resolve"
    end
    if($arg0 == 5)
      	printf "Discard"
    end
    if($arg0 == 6)
     	printf "Composite"
    end
    if($arg0 == 7)
    	printf "Vrf_Translate"
    end
   	if($arg0 == 8)
     	printf "L2 Receive"
   	end
	if($arg0 == 9)
      	printf "Max"
  	end
end

#arg0: nh_family of cur_nh
define print_nh_family
	if ($arg0 == 2)
        printf "AF_INET"
	end
	if ($arg0 == 7)
        printf "AF_BRIDGE"
	end
	if ($arg0 == 10)
        printf "AF_INET6"
	end
end

#arg0: nh_flag of cur_nh
define print_nh_flags
	printf "Flags:"
    set $nh_flags = $arg0
	set $mpls_check = $cur_nh.nh_flags >> 26
    if(($nh_flags) & 1)
  		printf "Valid, "
	end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
       	printf "Policy, "
    end
#	0x000004 is free
	set $nh_flags = $nh_flags >> 1
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
        if($cur_nh.nh_type == 3)
            if ($mpls_check  & 1)
         		printf "MPLSo"
            end
            printf "MPLSoGRE, "
        end
   	end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
        printf "UDP"
    end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
       	printf "Multicast, "
    end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
     	if($cur_nh.nh_type == 3)
        	if ($mpls_check  & 1)
             	printf "MPLSo"
            end
            printf "MPLSoUDP, "
        end
	end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
      	printf "Vxlan, "
    end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
    	printf "Policy(R), "
    end
    set $nh_flags = $nh_flags >> 1
   	if(($nh_flags) & 1)
        if($cur_nh.nh_type == 6)
            printf "Fabric, "
        end
    end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
      	if($cur_nh.nh_type == 6)
          	printf "Ecmp, "
        end
   	end
 	set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
        if($cur_nh.nh_type == 6)
          	printf "LU Ecmp, "
        end
    end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
        if($cur_nh.nh_type == 6)
          	printf "Evpn, "
        end
    end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
        if($cur_nh.nh_type == 6)
          	printf "Encap, "
        end
    end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
        if($cur_nh.nh_type == 6)
        	printf "Tor, "
        end
    end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
      	printf "RouteLookup, "
    end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
    	printf "Unicast Flood, "
    end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
     	printf "Copy SIP, "
    end
 	set $nh_flags = $nh_flags >> 1
   	if(($nh_flags) & 1)
    	printf "Flow Lookup, "
   	end
    set $nh_flags = $nh_flags >> 1
   	if(($nh_flags) & 1)
      	printf "Pbb, "
    end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
    	printf "Mac Learn, "
    end
   	set $nh_flags = $nh_flags >> 1
   	if(($nh_flags) & 1)
     	printf "Etree Root, "
    end
   	set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
      	printf "Indirect, "
    end
    set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
   		printf "Evpn Control Word, "
    end
    set $nh_flags = $nh_flags >> 1
 	if(($nh_flags) & 1)
     	printf "Encrypt Traffic, "
    end
    set $nh_flags = $nh_flags >> 1
  	if(($nh_flags) & 1)
    	printf "l3_vxlan, "
    end
    set $nh_flags = $nh_flags >> 1
	set $nh_flags = $nh_flags >> 1
    if(($nh_flags) & 1)
     	printf "Validate McastSrc"
    end
end

#arg0:nh_type, arg1:nh_family, arg2:nh_flags, arg3:nh_u
define get_union_type
#Encap
	if ($arg0 == 2)
        print_nh_encap_data $arg3.nh_encap
	end
#Tunnel
	if ($arg0 == 3)
        if (($arg2 >> 3) & 1)
            print_nh_gre_tunnel_data $arg3.nh_gre_tun
        end
        if (($arg2 >> 7) & 1)
            print_nh_vxlan_tunnel_data $arg3.nh_vxlan_tun
        end
       	if (($arg2 >> 19) & 1)
           	print_nh_pbb_tunnel_data $arg3.nh_pbb_tun
      	end
       	if (($arg2 >> 4) & 1)
            if ($arg1 == 2)
               	print_nh_udp_tunnel_data $arg3.nh_udp_tun 0
            end
            if ($arg1 == 10)
                print_nh_udp6_tunnel_data $arg3.nh_udp_tun6
            end
      	end
        if (($arg2 >> 6) & 1)
            print_nh_udp_tunnel_data $arg3.nh_udp_tun 1
        end
	end
#Composite
	if ($arg0 == 6)
        get_nh_comp_data $arg3.nh_composite
	end
end

#arg0:nh_encap of cur_nh
define print_nh_encap_data
	printf "\n            "
    printf "Len:%u EncapFmly:%u", $arg0.encap_len, $arg0.encap_family
end

#arg0:nh_gre_tun of cur_nh
define print_nh_gre_tunnel_data
	printf "\n            ScrIP:"
	get_ipv4 $arg0.tun_sip
	printf "DstIP:"
	get_ipv4 $arg0.tun_dip
	printf " Len:%u ", $arg0.tun_encap_len
	if (($cur_nh.nh_flags >> 26) & 1)
        printf "TransportLabel:%u", $arg0.transport_label
	end
end

#arg0:nh_vxlan_tun of cur_nh
define print_nh_vxlan_tunnel_data
	if ($arg0.udp_tun != 0)
        print_nh_udp_tunnel_data $arg0.udp_tun 0
	end
   	if (($cur_nh.nh_flags >> 25) & 1)
      	printf "L3Mac:"
     	print_mac_address $arg0.tun_l3_mac
    end
end

#arg0:nh_pbb_tun of cur_nh
define print_nh_pbb_tunnel_data
	printf "\n            PbbLabel:%d PbbMac:", $arg0.tun_pbb_label
	get_mac_address $arg0.tun_pbb_mac
end

#arg0:nh_udp_tun of cur_nh, arg1:flag(0 = No MPLS, 1 = MPLS)
define print_nh_udp_tunnel_data
	printf "\n            SrcIP:"
 	get_ipv4 $arg0.tun_sip
   	printf "DstIP:"
 	get_ipv4 $arg0.tun_dip
	printf "\n            Len:%u ", $arg0.tun_encap_len
	if ($arg1 == 0)
        printf "SrcPort:%u DstPort:%u", $arg0.tun_sport, $arg0.tun_dport
	end
	if ($arg1 == 1)
        if (($cur_nh.nh_flags >> 26) & 1)
            printf "TransportLabel:%u", $arg0.transport_label
        end
	end
end

#arg0:nh_udp_tun6 of cur_nh
define print_nh_udp6_tunnel_data
	if ($arg0.tun_sip6 != 0)
        printf "\n            SrcIPv6:"
        print_ipv6 $arg0.tun_sip6
	end
	if ($arg0.tun_dip6 != 0)
        printf "\n            DstIPv6:"
      	print_ipv6 $arg0.tun_dip6
	end
	printf "\n            SrcPort:%u ", $arg0.tun_sport6
    printf "DstPort:%u Len:%u", $arg0.tun_dport6, $arg0.tun_encap_len
end

#arg0:nh_composite of cur_nh
define get_nh_comp_data
   	set $cnh_count = 0
	get_nh_comp_config_hash $arg0.ecmp_config_hash
    while ($cnh_count < $arg0.cnt)
       	set $cur_cnh = $arg0.component[$cnh_count]
        printf "\n            Sub NH:%u ", $cur_cnh.cnh.nh_id
        printf "Label:%d ", $cur_cnh.cnh_label
        printf "EcmpIndex:%d ", $cur_cnh.cnh_ecmp_index
        set $cnh_count = $cnh_count + 1
   	end
end

#arg0:ecmp_hash_config of cur_nh
define get_nh_comp_config_hash
	if($arg0)
        printf "\n            EcmpCfg:"
	end
	set $mask_val_hash = 1
	if ($arg0 & $mask_val_hash)
        printf "Protocol, "
	end
	set $mask_val_hash = $mask_val_hash << 1
  	if ($arg0 & $mask_val_hash)
      	printf "Src IP, "
  	end
  	set $mask_val_hash = $mask_val_hash << 1
	if ($arg0 & $mask_val_hash)
    	printf "Src Port, "
 	end
  	set $mask_val_hash = $mask_val_hash << 1
	if ($arg0 & $mask_val_hash)
   		printf "Dst IP, "
	end
    set $mask_val_hash = $mask_val_hash << 1
 	if ($arg0 & $mask_val_hash)
    	printf "Dsp Port"
  	end
end

#arg0:ipv4 in decimal
define get_ipv4
	printf "%d.%d.", ($arg0 & 0xff), ($arg0 >> 8) & 0xff
    printf "%d.%d ", ($arg0 >> 16) & 0xff, ($arg0 >> 24)  & 0xff
end




