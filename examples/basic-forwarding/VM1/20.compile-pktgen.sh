#!/bin/bash
##
## Compile Pktgen-DPDK Script
## Copyright (c) 2014 Semihalf. All rights reserved.
##

. 00.config.sh


export RTE_SDK="${PKTGEN_SDK}"
export RTE_TARGET="${PKTGEN_TARGET}"

# Compile DPDK
(cd ${RTE_SDK} && make install T=${RTE_TARGET} -j 4)

# Compile Pktgen
(cd ${RTE_SDK}/examples/pktgen && make)
