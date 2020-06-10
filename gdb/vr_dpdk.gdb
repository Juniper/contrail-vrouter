#   File: "vr_dpdk.gdb"
#   This file contains the gdb macros to dump the global vrouter dpdk structure.

define dump_dpdk_global
    printf "\nDpdk Info:\n\n"
    printf "vlan_tag:%hd\nvtest_vlan:%hd\n", vr_dpdk.vlan_tag, vr_dpdk.vtest_vlan
    printf "Counters:\n    forward_lcores:%hd\n", vr_dpdk.nb_fwd_lcores
    printf "    io lcores:%hd\n", vr_dpdk.nb_io_lcores
    printf "    free_mempools:%hd\n", vr_dpdk.nb_free_mempools
    printf "uvhost_event_fd:%d\n", vr_dpdk.uvhost_event_fd
    printf "tap_nl_fd:%d\n", vr_dpdk.tap_nl_fd
    printf "vf_lcore_id:%u\n", vr_dpdk.vf_lcore_id
    printf "rss_mempool:%p\n", vr_dpdk.rss_mempool
    printf "packet_ring:%p\n", vr_dpdk.packet_ring
    printf "lcores_array_addr:%p", &(vr_dpdk.lcores)
    printf "    size:%d\n", (sizeof(vr_dpdk.lcores)/sizeof(vr_dpdk.lcores[0]))
    printf "frag_direct_mempool:%p\n", vr_dpdk.frag_direct_mempool
    printf "frag_indirect_mempool:%p\n", vr_dpdk.frag_indirect_mempool
    printf "ethdevs_array_addr:%p", &(vr_dpdk.ethdevs)
    printf "    size:%d\n", (sizeof(vr_dpdk.ethdevs)/sizeof(vr_dpdk.ethdevs[0]))
    printf "tapdevs_array_addr:%p", &(vr_dpdk.tapdevs)
    printf "    size:%d\n", (sizeof(vr_dpdk.tapdevs)/sizeof(vr_dpdk.tapdevs[0]))
    printf "vlan:\n    name:%s\n    dev:%p\n", vr_dpdk.vlan_name, vr_dpdk.vlan_dev
    printf "    vif:%p", vr_dpdk.vlan_vif
    if(vr_dpdk.vlan_vif)
        printf " id:%u\n", vr_dpdk.vlan_vif.vif_idx
    else
        printf "\n"
    end
    printf "\n"
end

document dump_dpdk_global
Syntax:dump_dpdk_global
No. of arguments:0

end

#arg0:rte_mempool object
define dump_rte_mempool
    printf "\nMempool name:%s\n", $arg0.name
    printf "flags:%u\npool:%p\n", $arg0.flags, $arg0.pool_data
    printf "iova:%p\n", $arg0.mz.iova
    printf "nb_mem_chunks:%u\n", $arg0.nb_mem_chunks
    printf "size:%lu\npopulated_size:%lu\n", $arg0.size, $arg0.populated_size
    printf "header_size:%lu\nelt_size:%lu\n", $arg0.header_size, $arg0.elt_size
    printf "trailer_size:%lu\n", $arg0.trailer_size
    set $total_obj_size = $arg0.header_size + $arg0.elt_size + $arg0.trailer_size
    printf "total_obj_size:%lu\n", $total_obj_size
    printf "private_data_size:%lu\n", $arg0.private_data_size
    printf "internal cache infos:\n"
    printf "    cache_size:%lu\n", $arg0.cache_size
    set $tot_cache_count = 0
    if($arg0.cache_size > 0)
        set $lcore_id = 0
        set $rte_max_lcore = 128
        while($lcore_id < $rte_max_lcore)
            set $cache_count = $arg0.local_cache[$lcore_id].len
            printf "    cache_count[%u]:%lu\n", $lcore_id, $cache_count
            set $tot_cache_count += $cache_count
            set $lcore_id += 1
        end
        printf "    total_cache_count:%lu\n", $tot_cache_count
    end
    set $ops = (struct rte_mempool_ops *)(&rte_mempool_ops_table.ops[$arg0.ops_index])
    set $common_count = 0
    set $pooldata_ring = (struct rte_ring *)($arg0.pool_data)
    rte_mempool_ops_get_count $pooldata_ring $common_count
    if(($tot_cache_count + $common_count) > $arg0.size)
        set $common_count = $arg0.size - $tot_cache_count
    end
    printf "common_pool_count:%u\n", $common_count
    printf "\n"
end

document dump_rte_mempool
Syntax:dump_rte_mempool rte_mempool_object
No. of arguments:1

end

#arg0:rte_ring object
define dump_rte_ring
    if($arg0 != 0)
    printf "\nRing name:%s\nsize:%u\n",$arg0.name, $arg0.size
    printf "capacity:%u\nflags:%d\n", $arg0.capacity, $arg0.flags
    printf "Producer:   head:%-4u tail:%-4u ", $arg0.prod.head, $arg0.prod.tail
    printf "single:%u\n", $arg0.prod.single
    printf "Consumer:   head:%-4u tail:%-4u ", $arg0.cons.head, $arg0.cons.tail
    printf "single:%u\n", $arg0.cons.single
    set $used_val = 0
    rte_mempool_ops_get_count $arg0 $used_val
    set $free_val = (uint32_t)($arg0.capacity - $used_val)
    printf "used:%u\navail:%u\n", $used_val, $free_val
    printf "\n"
    end
end

document dump_rte_ring
Syntax:dump_rte_ring rte_ring_object
No. of arguments:1

end

#arg0:rte_ring pointer
define rte_mempool_ops_get_count
    set $ring_count = (uint32_t)(($arg0.prod.tail - $arg0.cons.tail)&($arg0.mask))
    set $ops_get_count = $arg0.capacity
    if($ring_count <= $arg0.capacity)
        set $ops_get_count = $ring_count
    end
    set $arg1 = $ops_get_count
end

#No arguments
define dump_dpdk_ethdev_all
    printf "\nEthdev List\n\n"
    set $rte_max_ethports = 32
    set $ethdev_iter = 0
    while($ethdev_iter < $rte_max_ethports)
        if(vr_dpdk.ethdevs[$ethdev_iter].ethdev_ptr)
            printf "ethdev ID:%d\n", $ethdev_iter
            dump_dpdk_ethdev vr_dpdk.ethdevs[$ethdev_iter]
        end
        set $ethdev_iter += 1
    end
end

document dump_dpdk_ethdev_all
Syntax:dump_dpdk_ethdev_all
No. of arguments:0

end

#No arguments
define dump_dpdk_tapdev_all
    printf "\nTapdev List\n\n"
    set $max_tap_if = 16
    set $tapdev_iter = 0
    while($tapdev_iter < $max_tap_if)
        if(vr_dpdk.tapdevs[$tapdev_iter].tapdev_fd)
            printf "tapdev ID:%d\n", $tapdev_iter
            dump_dpdk_tapdev vr_dpdk.tapdevs[$tapdev_iter]
        end
        set $tapdev_iter += 1
    end
end

document dump_dpdk_tapdev_all
Syntax:dump_dpdk_tapdev_all
No. of arguments:0

end

#No arguments
define dump_dpdk_lcore_all
    printf "\nLcore List\n\n"
    set $vr_max_cpus = 64
    set $lcore_iter = 0
    while($lcore_iter < $vr_max_cpus)
        if(vr_dpdk.lcores[$lcore_iter])
            printf "lcore ID:%d\n", $lcore_iter
            dump_dpdk_lcore vr_dpdk.lcores[$lcore_iter]
        end
        set $lcore_iter += 1
    end
end

document dump_dpdk_lcore_all
Syntax:dump_dpdk_lcore_all
No. of arguments:0

end

#arg0:vr_dpdk_ethdev
define dump_dpdk_ethdev
    dump_rte_ethdev_internal $arg0.ethdev_ptr $arg0.ethdev_nb_rss_queues
    printf "reta_size:%hu\n", $arg0.ethdev_reta_size
    printf "nb_slaves:%hd\n", $arg0.ethdev_nb_slaves
    if($arg0.ethdev_nb_slaves)
        print_ethdev_slave_ids $arg0.ethdev_nb_slaves $arg0.ethdev_slaves
    end
    printf "ethdev_vif_id:%hu\n", $arg0.ethdev_vif_idx
    printf "\n"
end

document dump_dpdk_ethdev
Syntax:dump_dpdk_ethdev vr_dpdk_ethdev_ptr
No. of arguments:1

end

#arg0:ethdev_nb_slaves, arg1:ethdev_slaves array
define print_ethdev_slave_ids
    printf "slaves:"
    set $slave_iter = 0
    while($slave_iter<$arg0)
        printf "%d, ", $arg1[$slave_iter++]
    end
    printf "\n"
end

#arg0:rte_ethdev pointer
define dump_rte_ethdev
    dump_rte_ethdev_internal $arg0 -1
end

document dump_rte_ethdev
Syntax:dump_rte_ethdev rte_ethdev_ptr
No. of arguments:1

end

#arg0:rte_ethdev pointer,  arg1:nb_rss_queues
define dump_rte_ethdev_internal
    print_rte_ethdev_data $arg0.data $arg0.device.driver
    if($arg1 >= 0)
        printf "nb_rss_queues:%hu\n", $arg1
    end
    print_rte_eth_stats $arg0.data $arg0.device.driver
end

#arg0:rte_ethdev.data pointer, $arg1:rte_ethdev.driver pointer
define print_rte_ethdev_data
    printf "name:%s\nport_id:%hu\nmac: ", $arg0.name, $arg0.port_id
    mac_address $arg0.mac_addrs.addr_bytes
    printf "\nmtu:%hu\nsocket_id:%d\n", $arg0.mtu, $arg0.numa_node
    if($arg0.hash_mac_addrs != 0)
        printf "hash_mac: "
        mac_address $arg0.hash_mac_addrs.addr_bytes
        printf "\n"
    end
    printf "driver:%s\n", $arg1.name
    print_rte_eth_dev_data_flags $arg0
    print_rte_eth_link $arg0.dev_link
    print_rte_eth_dev_vlan_offload $arg0.dev_conf.rxmode.offloads
    
    printf "nb_rx_queues:%hu\n", $arg0.nb_rx_queues
    printf "nb_tx_queues:%hu\n", $arg0.nb_tx_queues
    printf "rx_queues:%p\ntx_queues:%p\n", $arg0.rx_queues, $arg0.tx_queues
    printf "dev_private:%p\n", $arg0.dev_private

end

#arg0:rte_eth_dev_data pointer
define print_rte_eth_dev_data_flags
    printf "Flags(enabled):"
    if($arg0.promiscuous)
        printf "promiscuous, "
    end
    if($arg0.scattered_rx)
        printf "scattered_rx, "
    end
    if($arg0.all_multicast)
        printf "all_multicast, "
    end
    if($arg0.dev_started)
        printf "dev_started, "
    end
    if($arg0.lro)
        printf "lro"
    end
    printf "\n"
end

#arg0:rte_eth_link
define print_rte_eth_link
    printf "eth link info:\n"
    printf "    link_speed:%u\n", $arg0.link_speed
    printf "    link_duplex:"
    if($arg0.link_duplex)
        printf "full\n"
    else
        printf "half\n"
    end
    printf "    link_autoneg:"
    if($arg0.link_autoneg)
        printf "autonegotiated\n"
    else
        printf "fixed\n"
    end
    printf "    link_status:"
    if($arg0.link_status)
        printf "up\n"
    else
        printf "down\n"
    end
end

#arg0:dev_conf.rxmode.offloads
define print_rte_eth_dev_vlan_offload
    set $vlan_strip_offload_mask = 1
    set $vlan_filter_offload_mask = (1 << 9)
    set $vlan_extend_offload_mask = (1 << 10)
    printf "VLAN offload: \n"
    if($arg0 & $vlan_strip_offload_mask)
        printf "    strip on\n"
    else
        printf "    strip off\n"
    end
    if($arg0 & $vlan_filter_offload_mask)
        printf "    filter on\n"
    else
        printf "    filter off\n"
    end
    if($arg0 & $vlan_extend_offload_mask)
        printf "    qinq(extend) on\n"
    else
        printf "    qinq(extend) off\n"
    end
end

#arg0:rte_eth_data, arg1:driver
define print_rte_eth_stats
#set $eth_stats = (struct rte_eth_stats)(0)
#The above doesn't work! Check structure declaration Again
    set $eth_stats = {0,0,0,0,0,0,0}
    set $stats_set = 0
#order of eth_stats: ipackets, opackets, ibytes, obytes, imissed, ierrors, oerrors
    if($_streq($arg1.name, "net_bonding"))
        set $internal = (struct bond_dev_private *)($arg0.dev_private)
        set $slave_name = ""
        if($internal.slave_count)
            set $slave_port_id = $internal.slaves[0].port_id
            set $slave_name = rte_eth_devices[$slave_port_id].device.driver.name
        end
        set $slave_stats = {0,0,0,0,0,0,0}
        set $slavecounter = 0
        if($_streq($slave_name, "net_ixgbe"))
            set $stats_set = 1
            while($slavecounter < $internal.slave_count)
                set $cur_slave = $rte_rth_devices[$slave_port_id]
                eth_ixgbe_get_stats $slave_stats $cur_slave.data.dev_private
                eth_sum_bond_stats $eth_stats $slave_stats
                set $slavecounter += 1
            end
        end
        if($_streq($slave_name, "net_igb"))
            set $stats_set = 1
            while($slavecounter < $internal.slave_count)
                set $cur_slave = $rte_rth_devices[$slave_port_id]
                eth_igb_get_stats $slave_stats $cur_slave.data.dev_private
                eth_sum_bond_stats $eth_stats $slave_stats
                set $slavecounter += 1
            end
        end
    end

    if($_streq($arg1.name, "net_ixgbe"))
        set $stats_set = 1
        eth_ixgbe_get_stats $eth_stats $arg0.dev_private
    end

    if($_streq($arg1.name, "net_e1000_igb"))
        set $stats_set = 1
        eth_igb_get_stats $eth_stats $arg0.dev_private
        #set $igb_stats = (struct e1000_hw_stats *)((struct e1000_adapter *)($arg0.dev_private)).stats)
    end
    
    if($stats_set == 1)
        printf "%s Stats:\n", $arg1.name
        printf "    ipackets:%llu\n", $eth_stats[0]
        printf "    opackets:%llu\n", $eth_stats[1]
        printf "    ibytes:%llu\n", $eth_stats[2]
        printf "    obytes:%llu\n", $eth_stats[3]
        printf "    imissed:%llu\n", $eth_stats[4]
        printf "    ierrors:%llu\n", $eth_stats[5]
        printf "    oerrors:%llu\n", $eth_stats[6]
    else
        printf "Stats: Functionality not implemented for %s driver type!\n", $arg1.name
    end
end

#arg0:eth_stats, arg1:slave_stats
define eth_sum_bond_stats
    set $sum_index = 0
    while($sum_index<7)
        set $arg0[$sum_index] += $arg1[$sum_index]
        set $sum_index += 1
    end
end

#arg0:rte_eth_stats, arg1:dev_private
define eth_igb_get_stats
    set $igb_adapter = (struct e1000_adapter *)($arg1)
    set $igb_hw = (struct e1000_hw *)($igb_adapter.hw)
    set $igb_stats = (struct e1000_hw_stats *)($igb_adapter.stats)
    if($igb_stats)
        set $eth_stats[0] = $igb_stats.gprc
        set $eth_stats[1] = $igb_stats.gptc
        set $eth_stats[2] = $igb_stats.gorc
        set $eth_stats[3] = $igb_stats.gotc
        set $eth_stats[4] = $igb_stats.mpc

        set $eth_stats[5] = $igb_stats.crcerrs + $igb_stats.rlec + $igb_stats.ruc
        set $eth_stats[5] += $igb_stats.roc + $igb_stats.rxerrc
        set $eth_stats[5] += $igb_stats.algnerrc + $igb_stats.cexterr

        set $eth_stats[6] = $igb_stats.ecol + $igb_stats.latecol
    end
end

#arg0:rte_eth_stats, arg1:dev_private
define eth_ixgbe_get_stats
    set $ixgbe_adapter = (struct ixgbe_adapter *)($arg1)
    set $ixgbe_hw = (struct ixgbe_hw *)($ixgbe_adapter.hw)
    set $ixgbe_stats = (struct ixgbe_hw_stats *)($ixgbe_adapter.stats)
    if($ixgbe_stats)
        set $total_qprc = 0
        set $total_qbrc = 0
        set $total_qprdc = 0
        set $qprc_iter = 0
        while($qprc_iter < 16)
            set $total_qprdc += $ixgbe_stats.qprdc[$qprc_iter]
            set $total_qprc += $ixgbe_stats.qprc[$qprc_iter]
            set $total_qbrc += $ixgbe_stats.qbrc[$qprc_iter]
            set $qprc_iter += 1
        end

        set $eth_stats[0] = $total_qprc
        set $eth_stats[1] = $ixgbe_stats.gptc
        set $eth_stats[2] = $total_qbrc
        set $eth_stats[3] = $ixgbe_stats.gotc
        set $eth_stats[4] = $total_qprdc
    
        set $eth_stats[5] = $ixgbe_stats.crcerrs + $ixgbe_stats.mspdc
        set $eth_stats[5] += $ixgbe_stats.rlec + $ixgbe_stats.ruc
        set $eth_stats[5] += $ixgbe_stats.roc + $ixgbe_stats.illerrc
        set $eth_stats[5] += $ixgbe_stats.errbc + $ixgbe_stats.rfc
        set $eth_stats[5] += $ixgbe_stats.fccrc + $ixgbe_stats.fclast

        set $eth_stats[6] = 0
    end
end

#arg0:vr_dpdk_tapdev pointer
define dump_dpdk_tapdev
    printf "tapdev_fd:%d\n", $arg0.tapdev_fd
    printf "tapdev_vhost_fd:%d\n", $arg0.tapdev_vhost_fd
    printf "tapdev_vif_id:%u\n", $arg0.tapdev_vif.vif_idx
    printf "rx_ring:%p\n", $arg0.tapdev_rx_ring
    printf "tx_rings:\n"
    print_tapdev_tx_ring_list $arg0.tapdev_tx_rings
    printf "\n"
end

document dump_dpdk_tapdev
Syntax:dump_dpdk_tapdev vr_dpdk_tapdev_ptr
No. of arguments:1

end

#arg0:tapdev_tx_rings
define print_tapdev_tx_ring_list
    set $rlist_iter = 0
    printf "----------------------\n"
    printf "index |    tx_ring    \n"
    printf "----------------------\n"
    while($rlist_iter<128)
        if($arg0[$rlist_iter])
            printf "%-5d | %p \n", $rlist_iter, $arg0[$rlist_iter]
        end
        set $rlist_iter += 1
    end
    printf "----------------------\n"
end

#arg0:vr_dpdk_lcore pointer
define dump_dpdk_lcore
    print_dpdk_q_slist $arg0.lcore_rx_head 0
    print_dpdk_q_slist $arg0.lcore_tx_head 1
    printf "nb_rings_to_push:%hu\n", $arg0.lcore_nb_rings_to_push
    printf "nb_bonds_to_tx:%hu\n", $arg0.lcore_nb_bonds_to_tx
    printf "nb_rx_queues:%hu\n", $arg0.lcore_nb_rx_queues
    printf "lcore_cmd:%hu\ncmd_arg:%llu\n", $arg0.lcore_cmd, $arg0.lcore_cmd_arg
    printf "rx_ring:%p\n", $arg0.lcore_rx_ring
    printf "io_rx_ring:%p\n", $arg0.lcore_io_rx_ring
    printf "nb_fwd_loops:%llu\n", $arg0.lcore_fwd_loops
    printf "do_fragment_assembly:%d\n", $arg0.do_fragment_assembly
    print_dpdk_gro_ctrl $arg0.gro
    printf "nb_dst_lcores:%hu\n", $arg0.lcore_nb_dst_lcores
    if($arg0.lcore_nb_dst_lcores)
        print_dpdk_lcore_dst_lcores $arg0.lcore_dst_lcore_idxs $arg0.lcore_nb_dst_lcores
    end
    printf "\n"
end

document dump_dpdk_lcore
Syntax:dump_dpdk_lcore vr_dpdk.lcore_ptr
No. of arguments:1

end

#arg0:vr_dpdk_q_slist(rx or tx), $arg1:rx/tx flag:(0:rx, 1:tx)
define print_dpdk_q_slist
    set $cur_ele = $arg0.slh_first
    if($arg1 == 0)
        printf "rx list(vif_id: enabled): "
    else
        printf "tx list(vif_id: enabled): "
    end
    while($cur_ele)
        printf "(%u: %d),", $cur_ele.q_vif.vif_idx, $cur_ele.enabled
        set $cur_ele = $cur_ele.q_next.sle_next
    end
    printf "\n"
end

#arg0:gro_ctrl pointer
define print_dpdk_gro_ctrl
    printf "gro info:\n"
    printf "    count:%d\n", $arg0.gro_cnt
    printf "    flows:%d\n", $arg0.gro_flows
    printf "    tbl_v4_handle:%p\n", $arg0.gro_tbl_v4_handle
    printf "    tbl_v6_handle:%p\n", $arg0.gro_tbl_v6_handle
end

#arg0:lcore_dst_lcore_idx array, arg1:lcore_nb_dst_lcores
define print_dpdk_lcore_dst_lcores
    printf "dst_lcores:"
    set $dst_lcores_iter = 0
    while($dst_lcores_iter < $arg1)
        printf "%d, ", $arg0[$dst_lcores_iter] + (int)(VR_DPDK_FWD_LCORE_ID)
        set $dst_lcores_iter += 1
    end
    printf "\n"
end
