#!/bin/bash

sb_path=$PWD
cd $sb_path

## Set cover_flag=1 to skip all XML based testcases
export COVER_FLAG=1
scons --opt=coverage vrouter-ut

export VROUTER_DPDK_PATH=$(realpath $sb_path/build/coverage/vrouter/dpdk/contrail-vrouter-dpdk)
export VTEST_PATH=$(realpath $sb_path/build/coverage/vrouter/utils/vtest/vtest)

export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8

## Execute all python testcases
scons vrouter-py-ut:test

## Remove unwanted directories from coverage
cd build/coverage/vrouter
rm -rf utils/
rm -rf vtest/
rm -rf sandesh/
cd $sb_path

## Generate Coverage report
lcov --base-directory . --directory ./build/coverage/vrouter/ -c --ignore-errors gcov -o test.info
genhtml -o ./build/coverage/vrouter/ test.info

## Steps to generate coverage report in HTML format
echo "tar the $sb_path/build/coverage/vrouter directory and copy it to your local machine."
echo "untar it and open index.html to view coverage report in HTML format."
