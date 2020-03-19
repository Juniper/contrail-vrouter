#  	File: "vr_nexthop.gdb"
#	This file contains the gdb macros to dump the vrouter flow information.


set $flowtable = (struct vr_htable *)(router.vr_flow_table)

define dump_flow_all
	if(router)
     	printf "\nVRouter Flow Table\n\n"
     	set $r1 = router
       	set $i = 0
        set $j = 0
     	if($r1.vr_flow_table)
         	while($i < vr_flow_entries)
               	dump_flow_internal $i 0 $flowtable.ht_htable
               	set $i = $i + 1
           	end
            while($j < vr_oflow_entries)
                dump_flow_internal $j 0 $flowtable.ht_otable
                set $j = $j + 1
            end
      	end
	end
end

document dump_flow_all
Displays all the available flows in the vrouter in sequence
No. of arguments:0
end

define dump_flow_index
	if ($arg0 < vr_flow_entries)
        dump_flow_internal $arg0 1 $flowtable.ht_htable
    else
        set $oflow_index = $arg0 - vr_flow_entries
        dump_flow_internal $oflow_index 1 vr_flowtable.ht_otable
    end
end

document dump_flow_index
Syntax: dump_flow_index flow_id
Displays details of flow with id:flow_id
end

#arg0:flow_id, arg1:flag(0: dump all flows and hide some details,
#                        1: dump flow with flow_id with all details)
#arg2:btable pointer
define dump_flow_internal
   	set $cur_flow_addr = -1
 	get_index_addr_btable $arg2 $arg0 $cur_flow_addr
  	if($cur_flow_addr != -1)
     	set $cur_flow = (struct vr_flow_entry *)($cur_flow_addr)
       	if($cur_flow.fe_type != 0)
         	printf "ID:%-9dFlow:", $cur_flow.fe_hentry.hentry_index
         	get_flow_details $cur_flow.fe_key.key_u
        	print_flow_fe_flags $cur_flow.fe_flags
        	print_flow_fe_flags1 $cur_flow.fe_flags1
         	printf "\n            Action:"
         	print_flow_fe_action $cur_flow.fe_action
          	printf " rFlow:%d vrf:%u dvrf:%u", $cur_flow.fe_rflow, $cur_flow.fe_vrf, $cur_flow.fe_dvrf
         	if($arg1)
              	printf "\n            ttl:%u ", $cur_flow.fe_ttl
				printf "QosId:%d GenID:%u ", $cur_flow.fe_qos_id, $cur_flow.fe_gen_id
				printf "tcpSeq:%u", $cur_flow.fe_tcp_seq
				print_flow_tcp_flags $cur_flow.fe_tcp_flags
               	if ($cur_flow.fe_hold_list != 0)
                	printf " holdListVfqEntires:%u", $arg0.fe_hold_list[0].vfq_entries
				end
				printf "\n            MirrorID:%u, SecMirrorID:%u SrcNH:%lu", $cur_flow.fe_mirror_id, $cur_flow.fe_sec_mirror_id, $cur_flow.fe_src_nh_index
				printf "\n            Flow Stats: "
				printf "Bytes:%lu Packets:%lu ", $cur_flow.fe_stats.flow_bytes, $cur_flow.fe_stats.flow_packets
				printf "Bytes oflow:%u Packets oflow:%u", $cur_flow.fe_stats.flow_bytes_oflow, $cur_flow.fe_stats.flow_packets_oflow
				printf "\n            ecmpNH:%d, DropReason:%u Type:", $cur_flow.fe_ecmp_nh_index, $cur_flow.fe_drop_reason
				print_flow_fe_type $cur_flow.fe_type
				printf "\n            UDPsrcPort:%u SrcIP:", $cur_flow.fe_udp_src_port
				get_ipv4 $cur_flow.fe_src_info
				if ($cur_flow.fe_mme != 0)
					print_mirror_md_entry $cur_flow.fe_mme[0]
				end
             end
			printf "\n\n"
		end
	end
end

#arg0:fe_tcp_flags
define print_flow_tcp_flags
	set $flow_mask = 1
	printf "\n            tcpFlags:"
	if ($arg0 & $flow_mask)
		printf "FIN, "
	end
	set $flow_mask = $flow_mask << 1
   	if ($arg0 & $flow_mask)
       	printf "SYN, "
  	end
  	set $flow_mask = $flow_mask << 1
 	if ($arg0 & $flow_mask)
      	printf "RST, "
 	end
   	set $flow_mask = $flow_mask << 1
   	if ($arg0 & $flow_mask)
     	printf "PSH, "
  	end
   	set $flow_mask = $flow_mask << 1
  	if ($arg0 & $flow_mask)
     	printf "ACK, "
   	end
  	set $flow_mask = $flow_mask << 1
	if ($arg0 & $flow_mask)
      	printf "URG, "
   	end
    set $flow_mask = $flow_mask << 1
   	if ($arg0 & $flow_mask)
     	printf "ECN, "
    end
  	set $flow_mask = $flow_mask << 1
   	if ($arg0 & $flow_mask)
     	printf "CWR, "
 	end
end

#arg0:fe_flags
define print_flow_fe_flags
	printf "\n            Flags:"
	set $flow_mask = 1
	if ($arg0 & $flow_mask)
		printf "Active, "
	end
	set $flow_mask = $flow_mask << 1
  	if ($arg0 & $flow_mask)
     	printf "SNAT, "
  	end
  	set $flow_mask = $flow_mask << 1
  	if ($arg0 & $flow_mask)
    	printf "SPAT, "
	end
  	set $flow_mask = $flow_mask << 1
	if ($arg0 & $flow_mask)
    	printf "DNAT, "
 	end
   	set $flow_mask = $flow_mask << 1
   	if ($arg0 & $flow_mask)
    	printf "DPAT, "
 	end
  	set $flow_mask = $flow_mask << 1
 	if ($arg0 & $flow_mask)
    	printf "TrapECMP, "
  	end
 	set $flow_mask = $flow_mask << 1
  	if ($arg0 & $flow_mask)
    	printf "DeleteMarked, "
	end
  	set $flow_mask = $flow_mask << 1
  	if ($arg0 & $flow_mask)
    	printf "BgpService, "
   	end
   	set $flow_mask = $flow_mask << 1
    if ($arg0 & $flow_mask)
      	printf "Modified, "
  	end
  	set $flow_mask = $flow_mask << 1
    if ($arg0 & $flow_mask)
      	printf "NewFlow, "
   	end
   	set $flow_mask = $flow_mask << 1
	if ($arg0 & $flow_mask)
     	printf "Evict Candidate, "
 	end
  	set $flow_mask = $flow_mask << 1
   	if ($arg0 & $flow_mask)
      	printf "Evicted, "
  	end
   	set $flow_mask = $flow_mask << 1
 	if ($arg0 & $flow_mask)
      	printf "rFlow Valid, "
   	end
 	set $flow_mask = $flow_mask << 1
  	if ($arg0 & $flow_mask)
    	printf "Mirror, "
  	end
  	set $flow_mask = $flow_mask << 1
    if ($arg0 & $flow_mask)
   		printf "VRFT, "
  	end
  	set $flow_mask = $flow_mask << 1
 	if ($arg0 & $flow_mask)
   		printf "Link Local, "
  	end
end

#arg0:fe_flags1
define print_flow_fe_flags1
	set $flow_mask = 1
	set $flow_mask = $flow_mask << 12
	if ($arg0 & $flow_mask)
		printf "HbsLeft"
	end
	set $flow_mask = $flow_mask << 1
	if ($arg0 & $flow_mask)
		printf "HbsRight"
	end
end

#arg0:fe_action
define print_flow_fe_action
	if ($arg0 == 0)
		printf "Drop"
	end
	if ($arg0 == 1)
		printf "Hold"
	end
	if ($arg0 == 2)
		printf "Forward"
	end
	if ($arg0 == 3)
		printf "NAT"
	end
end

#arg0:fe_type
define print_flow_fe_type
	if ($arg0 == 0)
		printf "NULL"
	end
 	if ($arg0 == 1)
    	printf "ARP"
  	end
  	if ($arg0 == 2)
    	printf "IP"
	end
	if ($arg0 == 3)
    	printf "IP6"
  	end
	if ($arg0 == 4)
  		printf "IPoIP"
	end
  	if ($arg0 == 5)
     	printf "IP6oIP"
  	end
   	if ($arg0 == 6)
    	printf "AGENT"
   	end
	if ($arg0 == 7)
     	printf "PBB"
 	end
   	if ($arg0 == 8)
    	printf "Unknown"
  	end
end

#arg0:fe_key.key_u
define get_flow_details
	print_flow_common $arg0.ip_key
	if ($arg0.ip_key.ip_family == 2)
		get_flow_inet $arg0.ip4_key
	end
	if ($arg0.ip_key.ip_family == 10)
		get_flow_inet6 $arg0.ip6_key
	end
end

#arg0:fe_key.key_u.ip_key
define print_flow_common
	printf "\n             Family:"
	print_flow_family $arg0.ip_family
	printf " Protocol:%u NHid:%u", $arg0.ip_proto, $arg0.ip_nh_id
	printf "\n             SrcPort:%u DstPort:%u", $arg0.ip_sport, $arg0.ip_dport
end

#arg0:fe_key.key_u.ip_key.ip_family
define print_flow_family
	if ($arg0 == 1)
		printf "AF_UNIX"
	end
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

#arg0:fe_key.key_u.ip4_key
define get_flow_inet
	printf "\n             ScrIP:"
	get_ipv4 $arg0.ip4_sip
	printf " DstIP:"
	get_ipv4 $arg0.ip4_dip
end

#arg0:fe_key.key_u.ip6_key
define get_flow_inet6
	printf "\n             ScrIP:"
	print_flow_ipv6 $arg0.ip6_sip
	printf "\n             DstIP:"
	print_flow_ipv6 $arg0.ip6_dip
end

#arg0:usigned char ip6[16]
define print_flow_ipv6
   	set $count = 0
  	set $ipv6 = $arg0
 	while($count<16)
   		if($count == 8)
        	printf "\n                   "
      	end
       	if($count == 0 || $count == 8)
         	printf "%04x",$ipv6[$count]
     	else
         	printf ":%04x",$ipv6[$count]
       	end
      	set $count = $count + 1
 	end
end

#arg0:fe_mme[0]
define print_flow_mirror_md_entry
	printf "\n            MirrorMD:"
	set $md_count = 0
	while ($md_count < $arg0.mirror_md_len)
		printf "%x ", $arg0.mirror_md[$md_count++]
	end
	printf "\n           Mirror(SrcIP, SrcPort, vrf):"
	get_ipv4 $arg0.mirror_sip
	printf ", %u, %u", $arg0.mirror_sport, $arg0.mirror_vrf	
end





