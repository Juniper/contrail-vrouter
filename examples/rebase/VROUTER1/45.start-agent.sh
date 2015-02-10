#!/bin/bash
##
## Start vRouter Agent
## Copyright (c) 2015 Semihalf. All rights reserved.
##

. 00.config.sh

sudo service supervisor-vrouter stop
sudo -E ${AGENT}
