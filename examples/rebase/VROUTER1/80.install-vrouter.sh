#!/bin/bash
##
## Install vRouter
## Copyright (c) 2014 Semihalf. All rights reserved.
##

. 00.config.sh

sudo service supervisor-vrouter stop
sudo -E install ${VROUTER} /usr/bin
sudo service supervisor-vrouter start
