#!/bin/bash

vrouter_path=$VROUTER_DPDK_PATH
vtest_path=$VTEST_PATH
socket_path=$VROUTER_SOCKET_PATH
vtest_py_venv_path=$VTEST_PY_VENV_PATH
test_case_file=$1

Usage() {
   echo "Usage: run_test.sh [options]"
   echo "       --all , Run all tests"
   echo "       --pycodestyle, Run pycodestyle check"
   echo "       --flake, Run flake check"
   echo "       <test_file_name.py>, Run test file"
}

if [ -z "$vrouter_path" ]; then
   echo "vrouter path empty"
   Usage
   exit -1
elif [ -z "$vtest_path" ]; then
   echo "vtest path empty"
   Usage
   exit -1
elif [ -z "$socket_path" ]; then
   echo "scoket path empty"
   Usage
   exit -1
fi

if [ -z "$vtest_py_venv_path" ]; then
    vtest_py_venv_path="."
fi


echo "Running tests with following params:"
echo "VROUTER_DPDK_PATH: " $vrouter_path
echo "VTEST_PATH: " $vtest_path
echo "VROUTER_SOCKET_PATH: " $socket_path
echo "VTEST_PY_VENV_PATH: " $vtest_py_venv_path
echo "TEST PARAM: " $test_case_file

echo "Entering venv"
cd $vtest_py_venv_path
source ./bin/activate

export VROUTER_DPDK_PATH=$vrouter_path
export VTEST_PATH=$vtest_path
export VROUTER_SOCKET_PATH=$socket_path

if [ $test_case_file == "--all" ]; then
    echo "Executing all the tests in ./tests dir .."
    pytest ./tests/*
elif [ $test_case_file == "--pycodestyle" ]; then
    echo "Running pycodestyle check .."
    pycodestyle vtest_lib.py
    pycodestyle ./tests/*
elif [ $test_case_file == "--flake" ]; then
    echo "Running flake check .."
    flake8 vtest_lib.py
    flake8 ./tests/*
else
    echo "Executing test file $test_case_file .."
    pytest ./tests/$test_case_file
fi

echo "Exiting venv"
deactivate


