#/bin/sh


src_mac=`cat /etc/sysconfig/network-scripts/ifcfg-eth0| grep "HWADDR" | awk -F "=" '{print $2}'| awk -F ":" '{print $1 $2 $3 $4 $5 $6}'`
tap_mac=""
dst_mac=""
rt=0

create_tap_interface()
{
	local ifname=$1
	check=`ifconfig -a | grep $ifname |wc -l`
	if [ $check -eq "0" ]; then 
		ip tuntap add dev $ifname  mode tap
		if [ $? -ne "0" ]; then 
			echo "Tap creation has failed"
			exit 1 
		fi
	fi
}

get_mac()
{
	tap_mac=`ip link show  $1 | awk '/ether/ {print $2}' ` 
	dst_mac=`echo $tap_mac| awk -F ":" '{ print $1 $2 $3 $4 $5 $6 }'`
}
check_klm()
{
#	echo " checking for the KLM dependency.. " 
	ret=`lsmod | grep vrouter | wc -l`
	if [ $ret -eq "0" ]; then 
#		echo "inserting vrouter module"
		kern_version=`uname -a | awk '{ print $3}'`
#		echo $kern_version
		insmod /lib/modules/$kern_version/extra/net/vrouter/vrouter.ko
		if [ $? -ne "0" ]; then 
			echo "Not able to insert vrouter module"
			exit 1	
		fi
	fi
}
#assign_ip tap_interface_no ip prefix
assign_ip()
{
	if [ "$2" != "0.0.0.0" ]; then
	ifconfig tap$1 $2/$3
	fi
	if [ $? -ne "0" ]; then
	echo "ip address assignment to $1 has failed"
	fi
}
add_to_vif()
{
	local ifname=$1
	local tap_mac=$2
	local vrf=$3
	if [ "$ifname" =  "pkt0" ];then
	vif --add $ifname --mac $tap_mac --vrf $vrf --type agent	
	else
	vif --add $ifname --mac $tap_mac --vrf $vrf --type virtual
	fi
}
add_nh()
{
	local ifname=$1
	local nhid=$2
        oif=`vif --list | grep  $ifname | awk '{print $1}' | awk -F "/" '{ print $2}'`
        nh -c --nh=$nhid --oif=$oif --type=2 --smac=$src_mac --dmac=$dst_mac

}
add_rt()
{
	local nhid=$1
	local tap_ip=$2
	local vrf=$3
        if [ "$tap_ip"  != "0.0.0.0" ]; then
                rt -c -v $vrf -n $nhid -p $tap_ip -l 32
        else
                echo "not able to assing ip in the route"
                exit 1
        fi
}
add_vif_nh_rt()
{
	add_to_vif tap$1 $tap_mac $4
	add_nh tap$1 $1
	add_rt $1 $2  $4
}
create_interface()
{
	#$1=num ,$2= tap_ip,$3=prefix_len and $4=vrf	
        create_tap_interface tap$1
        get_mac tap$1
        assign_ip $1 $2 $3
        add_vif_nh_rt $1 $2 $3  $4
}
delete_specific_interface()
{
                ifid=`vif --list | grep $1 | awk '{print $1}' |awk -F "/" '{print $2}'`
                vif --delete $ifid
		if [ $2 -gt "0" ]; then
	                nh -d --nh $2
		fi
                ip tuntap del dev $1 mode tap

}
delete_interfaces()
{
	i=$1
	num=$[$1 + $2]
	while [ $i -lt $num ]
	do 
		delete_specific_interface tap$i $i
		i=$[$i + 1]
	done
}
setup()
{
	count=$1
	tap_ip=$2
	prefix_len=$3
	vrf=$4
	MaxValue=255
	num=$5
        baseaddr="$(echo $tap_ip | cut -d. -f1-3)"
        lsv="$(echo $tap_ip | cut -d. -f4)"

        while [ $count -gt "0" ]
        do
                if [ $lsv -eq $MaxValue ] ; then
                        echo "edge case needs to be written"
                fi
                tap_ip=$baseaddr.$lsv
                create_interface $num $tap_ip $3 $4
                lsv=$(( $lsv + 1 ))
                count=$(( $count - 1 ))
        	num=$[$num + 1]
                dev_name=tap$num
        done

}
udp_clean_up()
{
        rm /var/tmp/$3
        delete_interfaces $1  $2
}
check_return_code()
{
	count=`cat $1| grep "$2"| wc -l`
        if [ $count -eq "0" ]; then
                echo "$3 test case been failed"
		rt=1
        else
                echo "$3 test case has passed"
        fi
}
run_udp_test_case()
{
#create 2 interfaces , starting ip , prefixlen , vrf, and final parameter used for forming the tap interface name (which is also same as nh id)
	setup 2 25.25.25.1 24 0 3000
#running the receiver first
	python /root/udp_recv.py&
	sleep 1
	python /root/udp_send.py $tap_mac  25.25.25.1 25.25.25.2 tap3000 
	check_return_code /var/tmp/tap3001 sachin UDP
	if [ $rt -eq "1" ]; then 
                local pid=` ps -aef | grep "udp_recv.py"  | grep -v grep | awk '{print $2}'`
                kill $pid
	fi
	udp_clean_up 3000 2  tap3001
}
dhcp_clean_up()
{
	rm /var/tmp/pkt0
	delete_specific_interface pkt0 0
	delete_specific_interface tapdhcp 0
}
run_dhcp_test_case()
{
	create_tap_interface pkt0	
	get_mac pkt0
	tap_mac="00:00:5e:00:01:00"
	add_to_vif pkt0 $tap_mac 65535
	create_tap_interface tapdhcp
	get_mac tapdhcp
	add_to_vif tapdhcp $tap_mac 0
#we have to make these devices up as we haven't assigned the ip
	ifconfig tapdhcp up
	ifconfig pkt0 up
	sleep 1
	python /root/dhcp_server.py &
	python /root/dhcp_client.py $tap_mac tapdhcp
	check_return_code /var/tmp/pkt0	DHCPDISCOVER DHCP 
        if [ $rt -eq "1" ]; then
                local pid=` ps -aef | grep "dhcp_server.py"  | grep -v grep | awk '{print $2}'`
                kill $pid
        fi
	dhcp_clean_up

}
main()
{
	check_klm
	run_udp_test_case
	rt=0
	run_dhcp_test_case
}
main
exit 0

