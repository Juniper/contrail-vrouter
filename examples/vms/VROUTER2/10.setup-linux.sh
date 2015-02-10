#!/bin/bash
##
## Linux Setup Script
## Copyright (c) 2014 Semihalf. All rights reserved.
##
## - mount HugeTLBfs
## - configure hugepages
##

. 00.config.sh


#################################################################
## Mount HugeTLBfs
# check if already mounted
_mount=`mount | grep hugetlbfs`
if [ "x${_mount}" != "x" ]; then
    echo -e "HugeTLBfs is already mounted:\n${_mount}"
else
    echo "Mounting HugeTLBfs to ${TLBFS_DIR}..."
    sudo mkdir -p ${TLBFS_DIR}
    sudo mount -t hugetlbfs none ${TLBFS_DIR}
fi

#################################################################
## Configuring HugePages
echo
echo "Configuring ${NB_HUGEPAGES} HugePages..."
sudo -s bash -c "echo ${NB_HUGEPAGES} > /proc/sys/vm/nr_hugepages"
