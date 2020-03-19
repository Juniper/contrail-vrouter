vr_flow.gdb                                                                                         0000644 0000000 0000000 00000021417 13643556316 011731  0                                                                                                    ustar   root                            root                                                                                                                                                                                                                   #   File: "vr_flow.gdb"
#   This file contains the gdb macros to dump the vrouter flow information.


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
            printf " rFlow:%d", $cur_flow.fe_rflow
            printf " vrf:%u dvrf:%u", $cur_flow.fe_vrf, $cur_flow.fe_dvrf
            if($arg1)
                printf "\n            ttl:%u ", $cur_flow.fe_ttl
                printf "QosId:%d ", $cur_flow.fe_qos_id
                printf "GenID:%u ", $cur_flow.fe_gen_id
                printf "tcpSeq:%u", $cur_flow.fe_tcp_seq
                print_flow_tcp_flags $cur_flow.fe_tcp_flags
                if ($cur_flow.fe_hold_list != 0)
                    printf " holdListVfqEntires:%u", $arg0.fe_hold_list[0].vfq_entries
                end
                printf "\n            MirrorID:%u ", $cur_flow.fe_mirror_id
                printf "SecMirrorID:%u ", $cur_flow.fe_sec_mirror_id
                printf "SrcNH:%lu", $cur_flow.fe_src_nh_index
                printf "\n            Flow Stats: "
                printf "Bytes:%lu ", $cur_flow.fe_stats.flow_bytes
                printf "Packets:%lu ", $cur_flow.fe_stats.flow_packets
                printf "Bytes oflow:%u ", $cur_flow.fe_stats.flow_bytes_oflow
                printf "Packets oflow:%u",$cur_flow.fe_stats.flow_packets_oflow
                printf "\n            ecmpNH:%d ", $cur_flow.fe_ecmp_nh_index
                printf "DropReason:%u Type:", $cur_flow.fe_drop_reason
                print_flow_fe_type $cur_flow.fe_type
                printf "\n            UDPsrcPort:%u ",$cur_flow.fe_udp_src_port
                printf "SrcIP:"
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
                                                                                                                                                                                                                                                 vr_nexthop.gdb                                                                                      0000644 0000000 0000000 00000023435 13643564374 012454  0                                                                                                    ustar   root                            root                                                                                                                                                                                                                   #   File: "vr_nexthop.gdb"
#   This file contains the gdb macros to dump the vrouter nexthop information.


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
                                                                                                                                                                                                                                   vrouter.gdb                                                                                         0000644 0000000 0000000 00000000463 13643551765 011762  0                                                                                                    ustar   root                            root                                                                                                                                                                                                                   #   File: "vrouter.gdb"
#   Debugger sources this file. Make sure the source paths defined
#   below are correct before sourcing this file.

set print pretty
set height 0
source ~/vrouter_gdb/vr_btable.gdb
source ~/vrouter_gdb/vr_vif.gdb
source ~/vrouter_gdb/vr_nexthop.gdb
source ~/vrouter_gdb/vr_flow.gdb
                                                                                                                                                                                                             vr_vif.gdb                                                                                          0000644 0000000 0000000 00000054407 13643575160 011551  0                                                                                                    ustar   root                            root                                                                                                                                                                                                                   #   File: "vr_vif.gdb"
#   This file contains the gdb macros to dump the vrouter interface information.


define dump_vif_all
    if (router)
        set $r1 = router
        set $i= 0
        echo \n\nVRouter Interface Table\n\n
        while($i < $r1.vr_max_interfaces)
            dump_vif_internal $i 0
            set $i = $i + 1
        end
        echo \nNo more interfaces!\n
    end
end

document dump_vif_all
Displays all the available vifs in the vrouter in sequence
No. of arguments:0
end

define dump_vif_index
    dump_vif_internal $arg0 1
end

document dump_vif_index
Syntax: dump_vif_index vif_idx
Displays details of vif with id:vif_idx
end

#arg0:vif_idx, arg1:flag(0: dump all vifs and hide some details,
#			 1: dump vif with vif_idx with all details)
define dump_vif_internal
    if ($arg0)
        if(router.vr_interfaces[$arg0])
            set $cur_vif = (router.vr_interfaces[$arg0])
            set $int_ip = $cur_vif.vif_ip
            printf "\nvif 0/%-6uName:%s ", $cur_vif.vif_idx, $cur_vif.vif_name
            printf "IPaddr:%d.%d.", ($int_ip & 0xff), ($int_ip >> 8) & 0xff
            printf "%d.%d HWaddr:", ($int_ip >> 16) & 0xff, ($int_ip >> 24) & 0xff
            mac_address $cur_vif.vif_mac
            printf "GenNum:%u", $cur_vif.vif_gen
            printf "\n            Type:"
            print_vif_type (int)$cur_vif.vif_type
            printf " VLanID:%u OVlanID:%u", $cur_vif.vif_vlan_id, $cur_vif.vif_ovlan_id
            printf " Router:%#x, Users:%u", $cur_vif.vif_router, $cur_vif.vif_users
            printf "\n            "
            printf "Rid:%u NHid:%u ", $cur_vif.vif_rid, $cur_vif.vif_nh_id
            printf "Vrf:%u Mcast Vrf:%u ", $cur_vif.vif_vrf, $cur_vif.vif_mcast_vrf
            printf "MTU:%u Flags:", $cur_vif.vif_mtu
            print_vif_flags $cur_vif.vif_flags
            printf " OS_Id:%u\n", $cur_vif.vif_os_idx
            printf"            "
            print_vif_transport $cur_vif.vif_transport
            printf " QOS:%d", $cur_vif.vif_qos_map_index
            print_vhostuser_mode $cur_vif.vif_vhostuser_mode
            printf " vrfTableUsers:%u", $cur_vif.vif_vrf_table_users
            printf "\n            IPv6:"
            print_ipv6 $cur_vif.vif_ip6
            get_vif_stats $cur_vif.vif_stats
            if($arg1)
                get_drop_stats $cur_vif.vif_drop_stats $cur_vif.vif_pcpu_drop_stats
            end
            printf "            "
            vif_parent $cur_vif.vif_parent
            vif_bridge $cur_vif.vif_bridge
            printf "NumHWQueues:%u ", $cur_vif.vif_num_hw_queues
            print_hw_queues $cur_vif.vif_hw_queues

#FAT FLOW CFG AND EXCLUDE LIST MACRO CALLS HERE--------

            if ($cur_vif.fat_flow_cfg_size)
                get_fat_flow_cfg $cur_vif.fat_flow_cfg_size $cur_vif.fat_flow_cfg
            end

            if ($cur_vif.vif_fat_flow_ipv4_exclude_list_size || $cur_vif.vif_fat_flow_ipv6_exclude_list_size)
                printf "            Fat Flow Exclude List\n"
                get_fat_flow_exclude_list_ipv4 $cur_vif.vif_fat_flow_ipv4_exclude_list_size $cur_vif.vif_fat_flow_ipv4_exclude_plen_list $cur_vif.vif_fat_flow_ipv4_exclude_list
                get_fat_flow_exclude_list_ipv6 $cur_vif.vif_fat_flow_ipv6_exclude_list_size $cur_vif.vif_fat_flow_ipv6_exclude_plen_list $cur_vif.vif_fat_flow_ipv6_high_exclude_list $cur_vif.vif_fat_flow_ipv6_low_exclude_list
            end

#MIRROR METADATA --------
            if($cur_vif.vif_in_mirror_md_len)
                printf "            Ingress Mirror Metadata\n            "
                get_mirror_md $cur_vif.vif_in_mirror_md $cur_vif.vif_in_mirror_md_len
            end
            if($cur_vif.vif_out_mirror_md_len)
                printf "            Egress Mirror Metadata\n            "
                get_mirror_md $cur_vif.vif_out_mirror_md $cur_vif.vif_out_mirror_md_len
            end

#------------------------

            if ($cur_vif.vif_os || $cur_vif.vif_src_mac || $cur_vif.vif_pbb_mac[0])
                printf "\n            "
            end
            if ($cur_vif.vif_os)
                printf "OS:%#x ",$cur_vif.vif_os
            end
            if ($cur_vif.vif_src_mac)
                printf "SourceMAC:"
                mac_address $cur_vif.vif_src_mac
            end
            if ($cur_vif.vif_pbb_mac[0])
                printf "PbbMAC:"
                mac_address $cur_vif.vif_pbb_mac
            end

            if ($arg1)
                if ($cur_vif.vif_vrf_table)
                    print_vrf_table $curf_vif.vif_vrf_table
                end
                if ($cur_vif.vif_sub_interfaces)
                    print_sub_interfaces $cur_vif.vif_sub_interfaces
                end
            end
            printf "\n"
        end
    end
end

document dump_vif_internal
Syntax: dump_vif_internal vif_idx flag
Here, flag specifices whether this internal function is being called to display all the vifs or just one
end

#arg0:vif_type of cur_vif
define print_vif_type
    set $vif_num = $arg0
    if($vif_num == 0)
        printf "HOST"
    end
    if($vif_num == 1)
        printf "AGENT"
    end
    if($vif_num == 2)
        printf "PHYSICAL"
    end
    if($vif_num == 3)
        printf "VIRTUAL"
    end
    if($vif_num == 4)
        printf "XenLL"
    end
    if($vif_num == 5)
        printf "GATEWAY"
    end
    if($vif_num == 6)
        printf "STATS"
    end
    if($vif_num == 7)
        printf "VirtualVLAN"
    end
    if($vif_num == 8)
        printf "MONITER"
    end
    if($vif_num > 8)
        printf "INVALID"
    end
end

#arg0:uint8_t *vif_ip6
define print_ipv6
    set $count = 0
    set $vif_ipv6 = $arg0
    while($count<16)
        if($count == 8)
            printf "\n                 "
        end
        if($count == 0 || $count == 8)
            printf "%04x",$vif_ipv6[$count]
        else
            printf ":%04x",$vif_ipv6[$count]
        end
        set $count = $count + 1
    end
    printf "\n"
end

#arg0:uint8_t *mac
define mac_address
    printf "%02x:%02x:%02x:", $arg0[0], $arg0[1], $arg0[2]
    printf "%02x:%02x:%02x ", $arg0[3], $arg0[4], $arg0[5]
end

#arg0:vif_transport of cur_vif
define print_vif_transport
    printf "Transport:"
    if($arg0 == 0)
        printf "VIRTUAL"
    end
    if($arg0 == 1)
        printf "ETH"
    end
    if($arg0 == 2)
        printf "PMD"
    end
    if($arg0 == 3)
        printf "SOCKET"
    end
end

#arg0:vif_flags of cur_vif
define print_vif_flags
    set $flags = $arg0
    set $test_v = 1
    if(($flags) & 1)
        printf "P"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "X"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "S"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Mr"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Mt"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Tc"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "L3"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "L2"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "D"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Vp"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Pr"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Vnt"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Mnp"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Dpdk"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Rfl"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Mon"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Uuf"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Vof"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Df"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "L"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Proxy"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Er"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Gro"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Mrg"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Mn"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Ig"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "Md"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "HbsL"
    end
    set $flags = $flags >> 1
    if(($flags) & 1)
        printf "HbsR"
    end
end

#arg0:vif_parent of cur_vif
define vif_parent
    if($arg0)
        set $parent = (struct vr_interface *)($arg0)
        printf "Parent:vif 0/%u ", $parent.vif_idx
    end
end

#arg0:vif_bridge of cur_vif
define vif_bridge
    if($arg0)
        set $bridge = (struct vr_interface *)($arg0)
        printf "Bridge:vif 0/%u ", $bridge.vif_idx
    end
end

#arg0:vif_vrf_table of cur_vif
define print_vrf_table
    printf "\n"
    printf "            VRF Table: -----------------\n"
    printf "                        VRF | NextHopID \n"
    printf "                       -----------------\n"
    set $count = 0
    while($count < 1024)
        if ($arg0[$count].va_vrf != -1)
            printf "                       "
            printf "%4d | %10u\n", $arg0[$count].va_vrf, $arg0[$count].va_nh_id
        end
        set $count = $count + 1
    end
end

#arg0:vif_sub_interfaces pointer of cur_vif
define print_sub_interfaces
    printf "\n"
    set $count = 0
    printf "            Sub Interfaces: -----------------\n"
    printf "                             VLanID | VIF ID \n"
    printf "                            -----------------\n"
    while($count <= 65535)
        if($arg0[$count])
            printf "                             "
            printf "%-6u | %-6u \n", $arg0[$count].vif_vlan_id, $arg0[$count].vif_idx
        end
        set $count = $count + 1
    end
end

#arg0:vif_stats of cur_vif
define get_vif_stats
    printf "            Interface Stats\n"
    printf "                     Input: "
    printf "ibytes:%llu ipackets:%llu ", $arg0.vis_ibytes, $arg0.vis_ipackets
    printf "ierrors:%llu\n", $arg0.vis_ierrors
    printf "                    Output: "
    printf "obytes:%llu opackets:%llu ", $arg0.vis_obytes, $arg0.vis_opackets
    printf "oerrors:%llu\n", $arg0.vis_oerrors
    printf "                     Queue: "
    printf "ipackets:%llu ", $arg0.vis_queue_ipackets
    printf "ierrors:%llu ", $arg0.vis_queue_ierrors
    printf "opackets:%llu ", $arg0.vis_queue_opackets
    printf "oerrors:%llu\n", $arg0.vis_queue_oerrors
    printf "                            ierrorsToLCore:"
    set $count = 0
    while($count < vr_num_cpus)
        printf "%llu", $arg0.vis_queue_ierrors_to_lcore[$count++]
        if($count < vr_num_cpus)
            printf", "
        end
    end
    printf"\n"
    printf "                      Port: "
    printf "ipackets:%llu ierrors:%llu ", $arg0.vis_port_ipackets, $arg0.vis_port_ierrors
    printf "isyscalls:%llu inombufs:%llu", $arg0.vis_port_isyscalls, $arg0.vis_port_inombufs
    printf "\n                            opackets:%llu ", $arg0.vis_port_opackets
    printf "oerrors:%llu osyscalls:%llu\n", $arg0.vis_port_oerrors, $arg0.vis_port_osyscalls
    printf "                       Dev: "
    printf "ibytes:%llu ipackets:%llu ", $arg0.vis_dev_ibytes, $arg0.vis_dev_ipackets
    printf "ierrors:%llu inombufs:%llu", $arg0.vis_dev_ierrors, $arg0.vis_dev_inombufs
    printf "\n                            obytes:%llu ", $arg0.vis_dev_obytes
    printf "opackets:%llu oerrors:%llu\n", $arg0.vis_dev_opackets, $arg0.vis_dev_oerrors
end

#arg0:vif_vhostuser_mode of cur_vif
define print_vhostuser_mode
    set $mode = (vhostuser_mode_t)$arg0
    printf " vHostUserMode:"
    if((int)$mode == 0)
        printf "CLIENT"
    else
        printf "SERVER"
    end
end

#arg0:vif_hw_queues of cur_vif
define print_hw_queues
    if($arg0)
        set $count = 0
        printf " Q_Ids:"
        while($arg0[$count])
            printf " %u", $arg0[$count++]
        end
        printf "\n"
    end
end

#arg0:fat_flow_cfg len, arg11:fat_flow_cfg pointer
define get_fat_flow_config
    set $count = 0
    printf "\n            Fat Flow Config:\n"
    while($count < $arg0)
        set $cur_cfg = $arg1[$count]
        printf "                          %d:", $count
        printf " ProtocolNo:%u PortNo:%u\n", $cur_cfg.protocol, $cur_cfg.port
        set $aggr_info_val1 = ($cur_cfg.port_aggr_info & 0x03)
        set $aggr_info_val2 = ($cur_cfg.port_aggr_info & 0xF0) >> 4
        printf "                             PortAggrInfo:"
        check_validity_part1 $aggr_info_val1
        check_validity_part2 $aggr_info_val2
        printf "                             SrcPrefixInfo:"
        printf "\n                             IPAddr: "
        if ($cur_cfg.src_prefix_h)
            ipv6_hex_convert $cur_cfg.src_prefix_h
            printf "\n                                     "
            ipv6_hex_convert $cur_cfg.src_prefix_l
        else
            set $s_ip = $cur_cfg.src_prefix_l
            printf "%d.%d.", $s_ip & 0xff, ($s_ip >> 8) & 0xff
            printf "%d.%d", ($s_ip >> 16) & 0xff, ($s_ip >> 24) & 0xff
        end
        printf "\n                             "
        printf "PrefixMask:%u ", $cur_cfg.src_prefix_mask
        printf "AggrLen:%u\n", $cur_cfg.src_aggregate_plen
        printf "                             DstPrefixInfo:"
        printf "\n                             IPAddr:"
        if ($cur_cfg.dst_prefix_h)
            ipv6_hex_convert $cur_cfg.dst_prefix_h
            ipv6_hex_convert $cur_cfg.dst_prefix_l
        else
            set $d_ip = $cur_cfg.dst_prefix_l
            printf "%d.%d.", $d_ip & 0xff, ($d_ip >> 8) & 0xff
            printf "%d.%d\n", ($d_ip >> 16) & 0xff, ($d_ip >> 24) & 0xff
        end
        printf "                             "
        printf "PrefixMask:%u ", $cur_cfg.dst_prefix_mask
        printf "AggrLen:%u\n", $cur_cfg.dst_aggregate_plen
        set $count = $count + 1
    end
end

#arg0:uint64_t high or low
#Displays only half ip6 address. Called twice
define ipv6_hex_convert
    set $c1 = 1
    set $flag = 0
    set $shift = 8
    while ($c1 <= 8)
        if ($flag)
            printf ":%04x", ($arg0 >> ($shift * $c1)) && 0xff
        else
            printf "%04x", $arg0 & 0xff
            set $flag = 1
        end
        set $c1 = $c1 + 1
    end
end

#arg0:Port aggr info(4 LSB)
define check_validity_part1
    if($arg0 == 0)
        printf "Port Invalid"
    end
    if($arg0 == 1)
        printf "Port SrcIP Ignore"
    end
    if($arg0 == 2)
        printf "Port DstIP Ignore"
    end
    if($arg0 == 3)
        printf "Port Set"
    end
    printf ", "
end

#arg0:Port aggr info(4 MSB)
define check_validity_part2
    if($arg0 == 0)
        printf "AggrNone"
    end
    if($arg0 == 1)
        printf "AggrDstIPv6"
    end
    if($arg0 == 2)
        printf "AggrSrcIPv6"
    end
    if($arg0 == 3)
        printf "AggrSrcDstIPv6"
    end
    if($arg0 == 4)
        printf "AggrDstIPv4"
    end
    if($arg0 == 5)
        printf "AggrDstIPv4"
    end
    if($arg0 == 6)
        printf "AggrSrcDstIPv4"
    end
    printf "\n"
end

#Fat Flow Exclude details ipv4
#arg0:exclude list size, arg1:plen list, arg4:exclude list
define get_fat_flow_exclude_list_ipv4
    if ($arg0)
        printf "            IPv4\n"
        set $count = 0
        while($count < $arg0)
            set $ip = $arg2[$count]
            printf "            %d.%d.", ($ip & 0xff), ($ip >> 8) & 0xff
            printf "%d.%d", ($ip >> 16) & 0xff, ($ip & 24) & 0xff
            printf "/%u\n", $arg1[$count++]
        end
    end
end

#Fat Flow Exclude List ipv6
#arg0:size, arg1:plen list, arg2:exclude list for ipv6(high), arg3:exclude list for ipv6(low)
define get_fat_flow_exclude_list_ipv6
    if($arg0)
        printf "            IPv6\n"
        set $count = 0
        while ($count < $arg0)
            printf "            "
            ipv6_hex_convert $arg2[$count]
            printf "\n            "
            ipv6_hex_convirt $arg3[$count]
            printf "/%u\n", $arg1[$count++]
        end
    end
end

#Same function call for ingress and egress mirror metadata
#arg0:md pointer, arg1:md len
define get_mirror_md
    set $count = 0
    while($count<$arg1)
        printf "%x ", $arg0[$count]
    end
    printf "\n"
end

#arg0:vif_drop_stats pointer, arg1:vif_pcpu_drop_stats btable pointer
define get_drop_stats
    if($arg0 != 0)
        set $dsval = (unsigned long *)($arg0)
        printf "            Drop Stats"
        set $cur_ds = (uint64_t)(0)
        sum_pcpu_stat $arg1 0 $cur_ds
        printf " \n             Discards:%lu", $dsval[0] + $cur_ds
        sum_pcpu_stat $arg1 1 $cur_ds
        printf " Pull Fails:%lu", $dsval[1] + $cur_ds
        sum_pcpu_stat $arg1 2 $cur_ds
        printf " Invalid IF:%lu", $dsval[2] + $cur_ds
        set $cur_ds = 0
        sum_pcpu_stat $arg1 3 $cur_ds
        printf " Invalid ARP:%lu", $dsval[3] + $cur_ds
        sum_pcpu_stat $arg1 4 $cur_ds
        printf " \n             Trap No IF:%lu",$dsval[4] + $cur_ds
        sum_pcpu_stat $arg1 5 $cur_ds
        printf " Nowhere to go:%lu", $dsval[5] + $cur_ds
        sum_pcpu_stat $arg1 6 $cur_ds
        printf " Flow Queue Limit Exceeded:%lu", $dsval[6] + $cur_ds
        sum_pcpu_stat $arg1 7 $cur_ds
        printf " \n             Flow No Memory:%lu", $dsval[7] + $cur_ds
        sum_pcpu_stat $arg1 8 $cur_ds
        printf " Flow Invalid Protocol:%lu", $dsval[8] + $cur_ds
        sum_pcpu_stat $arg1 9 $cur_ds
        printf " Flow NAT no rflow:%lu", $dsval[9] + $cur_ds
        sum_pcpu_stat $arg1 10 $cur_ds
        printf " \n             Flow Action Drop:%lu", $dsval[10] + $cur_ds
        sum_pcpu_stat $arg1 11 $cur_ds
        printf " Flow Action Invalid:%lu", $dsval[11] + $cur_ds
        sum_pcpu_stat $arg1 12 $cur_ds
        printf " Flow Unusable:%lu", $dsval[12] + $cur_ds
        sum_pcpu_stat $arg1 13 $cur_ds
        printf " \n             Flow Table Full:%lu", $dsval[13] + $cur_ds
        sum_pcpu_stat $arg1 14 $cur_ds
        printf " IF TX Discard:%lu", $dsval[14] + $cur_ds
        sum_pcpu_stat $arg1 15 $cur_ds
        printf " IF Drop:%lu", $dsval[15] + $cur_ds
        sum_pcpu_stat $arg1 16 $cur_ds
        printf " Duplicated:%lu", $dsval[16] + $cur_ds
        sum_pcpu_stat $arg1 17 $cur_ds
        printf " \n             Push Fails:%lu", $dsval[17] + $cur_ds
        sum_pcpu_stat $arg1 18 $cur_ds
        printf " TTL Exceeded:%lu", $dsval[18] + $cur_ds
        sum_pcpu_stat $arg1 19 $cur_ds
        printf " Invalid NH:%lu", $dsval[19] + $cur_ds
        sum_pcpu_stat $arg1 20 $cur_ds
        printf " Invalid Label:%lu", $dsval[20] + $cur_ds
        sum_pcpu_stat $arg1 21 $cur_ds
        printf " \n             Invalid Protocol:%lu", $dsval[21] + $cur_ds
        sum_pcpu_stat $arg1 22 $cur_ds
        printf " IF RX Discard:%lu", $dsval[22] + $cur_ds
        sum_pcpu_stat $arg1 23 $cur_ds
        printf " Invalid Mcast Source:%lu", $dsval[23] + $cur_ds
        sum_pcpu_stat $arg1 24 $cur_ds
        printf " \n             Head Alloc Fails:%lu", $dsval[24] + $cur_ds
        sum_pcpu_stat $arg1 25 $cur_ds
        printf " PCOW fails:%lu", $dsval[25] + $cur_ds
        sum_pcpu_stat $arg1 26 $cur_ds
        printf " Jumbo Mcast Pkt with DF Bit:%lu", $dsval[26] + $cur_ds
        sum_pcpu_stat $arg1 27 $cur_ds
        printf " \n             Mcast Clone Fail:%lu", $dsval[27] + $cur_ds
        sum_pcpu_stat $arg1 28 $cur_ds
        printf " Memory Failures:%lu", $dsval[28] + $cur_ds
        sum_pcpu_stat $arg1 29 $cur_ds
        printf " Rewrite Fail:%lu", $dsval[29] + $cur_ds
        sum_pcpu_stat $arg1 30 $cur_ds
        printf " Misc:%lu", $dsval[30] + $cur_ds
        sum_pcpu_stat $arg1 31 $cur_ds
        printf " \n             Invalid Packets:%lu", $dsval[31] + $cur_ds
        sum_pcpu_stat $arg1 32 $cur_ds
        printf " Checksum errors:%lu", $dsval[32] + $cur_ds
        sum_pcpu_stat $arg1 33 $cur_ds
        printf " No Fmd:%lu", $dsval[33] + $cur_ds
        sum_pcpu_stat $arg1 34 $cur_ds
        printf " Cloned Original:%lu", $dsval[34] + $cur_ds
        sum_pcpu_stat $arg1 35 $cur_ds
        printf " \n             Invalid VNID:%lu", $dsval[35] + $cur_ds
        sum_pcpu_stat $arg1 36 $cur_ds
        printf " Fragment errors:%lu", $dsval[36] + $cur_ds
        sum_pcpu_stat $arg1 37 $cur_ds
        printf " Invalid Source:%lu", $dsval[37] + $cur_ds
        sum_pcpu_stat $arg1 38 $cur_ds
        printf " \n             No L2 Route:%lu", $dsval[38] + $cur_ds
        sum_pcpu_stat $arg1 39 $cur_ds
        printf " Fragment Queueing Failures:%lu", $dsval[39] + $cur_ds
        sum_pcpu_stat $arg1 40 $cur_ds
        printf " \n             VLAN fwd intf failed TX:%lu", $dsval[40] + $cur_ds
        sum_pcpu_stat $arg1 41 $cur_ds
        printf " VLAN fwd intf failed enq:%lu", $dsval[41] + $cur_ds
        sum_pcpu_stat $arg1 42 $cur_ds
        printf " \n             New Flow Drops:%lu", $dsval[42] + $cur_ds
        sum_pcpu_stat $arg1 43 $cur_ds
        printf " Flow Unusable (Eviction):%lu", $dsval[43] + $cur_ds
        sum_pcpu_stat $arg1 44 $cur_ds
        printf " \n             Original Packet Trapped:%lu", $dsval[44] + $cur_ds
        sum_pcpu_stat $arg1 45 $cur_ds
        printf " Etree Leaf to Leaf:%lu", $dsval[45] + $cur_ds
        sum_pcpu_stat $arg1 46 $cur_ds
        printf " \n             Bmac/ISID Mismatch:%lu", $dsval[46] + $cur_ds
        sum_pcpu_stat $arg1 47 $cur_ds
        printf " Packet Loop:%lu", $dsval[47] + $cur_ds
        sum_pcpu_stat $arg1 50 $cur_ds
        printf " Max:%lu", $dsval[50] + $cur_ds
        sum_pcpu_stat $arg1 48 $cur_ds
        printf " \n             No Encrypt Path Failures:%lu", $dsval[48] + $cur_ds
        sum_pcpu_stat $arg1 49 $cur_ds
        printf " Invalid HBS received packet:%lu", $dsval[49] + $cur_ds
    end
    printf "\n"
end

#arg0:PCPU btable, arg1:reason number, arg2:sum
define sum_pcpu_stat
    set $sum = (uint64_t)(0)
    set $cpu = 0
    set $max_ds = 50
    if($arg0)
        while($cpu<vr_num_cpus)
            set $cur_pcpu_ds = -1
            set $index = ($max_ds*$cpu) + $arg1
            get_index_addr_btable $arg0 $index $cur_pcpu_ds
            if($cur_pcpu_ds != -1)
                set $sum = $sum + (*(uint8_t *)$cur_pcpu_ds)
            end
            set $cpu = $cpu + 1
        end
    end
    set $arg2 = $sum
end
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         