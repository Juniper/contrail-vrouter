#! /usr/bin/env python

import operator
import argparse
import subprocess
import sys
import os
import warnings
import time
import re

def get_dpdk_vrouter_pid():
    cmd = "ps -aux | grep \"[c]ontrail-vrouter-dpdk --no-daemon\"| awk \'{print $2}\'"
    dpdk_vrouter_pid = subprocess.check_output(['bash','-c', cmd])
    dpdk_vrouter_pid = re.sub("[^0-9]+","", dpdk_vrouter_pid, flags=re.IGNORECASE)
    if dpdk_vrouter_pid == "":
        print "/!\ DPDK vRouter is not present!"
        sys.exit(1)
    return dpdk_vrouter_pid

def get_core_n():
    vrouter_core_n = 0
    dpdk_vrouter_pid = get_dpdk_vrouter_pid()
    cmd = "for tid in $(ps --no-headers -p {} -ww -L -olwp |sed \'s/$/ /\'); do taskset -cp $tid; done | grep -v '^.*[0-9]*-[0-9]*' | wc -l" .format(get_dpdk_vrouter_pid())
    vrouter_core_n = int(subprocess.check_output(['bash','-c', cmd]))
    if vrouter_core_n == 0:
        print "/!\ DPDK vRouter is not present!"
        sys.exit(1)
    return vrouter_core_n

def get_cpu_load_all(vif, core_n, timer):
    list1_tx=[]
    list1_rx=[]
    list2_tx=[]
    list2_rx=[]
    rx=[]
    tx=[]
    for i in range(core_n):
        cmd = 'vif --get '+ str(vif) + ' --core ' + str(i+10) + '| grep -i  \"\(TX\|RX\) packets\"'
        output = subprocess.check_output(['bash','-c', cmd])
        out = []
        out = output.replace(':', ' ').split()
        list1_tx.append(int(out[13]))
        list1_rx.append(int(out[4]))
        list1_tx.append(int(out[15]))
        list1_rx.append(int(out[6]))
        list1_tx.append(int(out[17]))
        list1_rx.append(int(out[8]))
    time.sleep(timer)
    for i in range(core_n):
        cmd = 'vif --get '+ str(vif) + ' --core ' + str(i+10) + '| grep -i  \"\(TX\|RX\) packets\"'
        output = subprocess.check_output(['bash','-c', cmd])
        out = []
        out = output.replace(':', ' ').split()
        list2_tx.append(int(out[13]))
        list2_rx.append(int(out[4]))
        list2_tx.append(int(out[15]))
        list2_rx.append(int(out[6]))
        list2_tx.append(int(out[17]))
        list2_rx.append(int(out[8]))
    for i in map(operator.sub, list2_rx, list1_rx):
         rx.append(i/int(timer))
    for i in map(operator.sub, list2_tx, list1_tx):
         tx.append(i/int(timer))
    return tx, rx

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--vif", help="vif number - only number after /", type=int,  default=0)
parser.add_argument("-t", "--time", help="time for test default 3 seconds",type=int,  default=3)
parser.add_argument("-c", "--cpu", help="number of CPUs - default 6",type=int, default=0)
parser.add_argument("-all", "--all_vifs", help="total CPU utilisation from all VIFs", action='store_true', default='False')
parsed_params, _ = parser.parse_known_args(sys.argv[1:])
vif = parsed_params.vif
timer = parsed_params.time 
core_n = parsed_params.cpu    
if int(core_n) == 0:
    core_n = get_core_n()
    
if parsed_params.all_vifs == True :
    cmd = 'vif -l|awk \'/tap/{print $1}\' | cut -d\'/\' -f2'
    output = subprocess.check_output(['bash','-c', cmd])
    out = []
    out = output.replace(':', ' ').split()
    out.append(0)
    core = []
    tran = []
    recv = []
    for i in range(core_n):
        core.append(0)
    for i in range(core_n):
        tran.append(0)
    for i in range(core_n):
        recv.append(0)
    for j in out:
        tx,rx = get_cpu_load_all(j,core_n,timer)
        for i in range(core_n):
           print "| VIF {:<3} |Core {:<3}| TX pps: {:<10}| RX pps: {:<10}| TX bps: {:<10}| RX bps: {:<10}| TX error: {:<10}| RX error {:<10}| " .format(j,i+1,tx[i*3],rx[i*3],tx[i*3+1]*8,rx[i*3+1]*8,tx[i*3+2],rx[i*3+2])
           tran[i] = tran[i] + tx[i*3]
           recv[i] = recv[i] + rx[i*3]
           core[i] = core[i] + tx[i*3] + rx[i*3]
    print "------------------------------------------------------------------------"
    print "|                                pps per Core                          |"
    print "------------------------------------------------------------------------"
    for cpu in range(core_n):
        print "|Core {:<3}|TX + RX pps: {:<10}| TX pps {:<10}| RX pps {:<10}|" .format(cpu+1, core[cpu], tran[cpu], recv[cpu])
    print "------------------------------------------------------------------------"
    print "|Total   |TX + RX pps: {:<10}| TX pps {:<10}| RX pps {:<10}|" .format(reduce(lambda x, y: x+y, core), reduce(lambda x, y: x+y, tran), reduce(lambda x, y: x+y, recv))       
    print "------------------------------------------------------------------------"

else: 
    tx,rx = get_cpu_load_all(vif,core_n,timer)
    total=[0,0,0,0,0,0]
    print "-------------------------------------------------------------------------------------------------------------------------------------"
    for i in range(core_n):
        total[0]+=tx[i*3]
        total[1]+=rx[i*3]
        total[2]+=tx[i*3+1]
        total[3]+=rx[i*3+1]
        total[4]+=tx[i*3+2]
        total[5]+=rx[i*3+2]
        print "|Core {:<3}| TX pps: {:<10}| RX pps: {:<10}| TX bps: {:<10}| RX bps: {:<10}| TX error: {:<10}| RX error {:<10}|" .format(i+1, tx[i*3], rx[i*3], tx[i*3+1], rx[i*3+1], tx[i*3+2], rx[i*3+2])
        print "-------------------------------------------------------------------------------------------------------------------------------------"
    print "|Total   | TX pps: {:<10}| RX pps: {:<10}| TX bps: {:<10}| RX bps: {:<10}| TX error: {:<10}| RX error {:<10}|" .format(total[0], total[1], total[2]*8, total[3]*8, total[4], total[5])
    print "-------------------------------------------------------------------------------------------------------------------------------------"


