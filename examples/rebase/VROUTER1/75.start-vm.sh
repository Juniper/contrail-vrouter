#!/bin/bash
##
## MPLSoUDP Scenario Test
## Copyright (c) 2015 Semihalf. All rights reserved.

. 00.config.sh

#################################################################
## Spawn a VM
sudo qemu-system-x86_64 -cpu host -smp 4 -enable-kvm \
    -drive if=virtio,file=vm.qcow2,cache=none \
    -object memory-backend-file,id=mem,size=1024M,mem-path=${TLBFS_DIR},share=on \
    -m 1024 \
    -numa node,memdev=mem \
    -chardev socket,id=charnet0,path=${UVH_PREFIX}_vm2 \
    -netdev type=vhost-user,id=hostnet0,chardev=charnet0 \
    -device virtio-net-pci,netdev=hostnet0,mac=${VM_MAC},csum=off
