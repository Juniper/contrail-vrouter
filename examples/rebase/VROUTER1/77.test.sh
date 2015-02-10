#!/bin/bash -x
##
## MPLSoUDP Scenario Test
## Copyright (c) 2015 Semihalf. All rights reserved.

. 00.config.sh

sudo ${RT} --dump 0
sudo ${RT} --dump 0 --family bridge
sudo ${DROPSTATS}
