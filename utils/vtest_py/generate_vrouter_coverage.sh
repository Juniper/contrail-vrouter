#!/bin/bash

sb_path=$PWD

## Set CODE_COVERAGE_RUN=1 to skip all XML based testcases
export CODE_COVERAGE_RUN=1
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

tar -cvf $sb_path/build/coverage/vrouter/coverage_report.tar $sb_path/build/coverage/vrouter
## Steps to generate coverage report in HTML format
echo "Copy the coverage_report.tar in $sb_path/build/coverage/vrouter/ directory
      to your local machine."
echo "Untar it and open index.html to view coverage report in HTML format."
