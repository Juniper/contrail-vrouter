#!/bin/bash
qemu-system-x86_64 -cpu host -smp 4 \
    -m 1024 -enable-kvm -drive if=virtio,file=vm2.qcow2,cache=none \
