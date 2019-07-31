#!/bin/bash

vrouter_path=$VROUTER_DPDK_PATH
vtest_path=$VTEST_PATH
socket_path=$VROUTER_SOCKET_PATH
vtest_py_venv_path=$VTEST_PY_VENV_PATH
vtest_only_mode=$VTEST_ONLY_MODE
vrouter_only_mode=$VROUTER_ONLY_MODE
test_opt=$1
sb_path=$PWD/../../../build

Usage() {
   echo
   echo "Usage: run_test.sh [options]"
   echo "       --all , Run all tests"
   echo "       --pycodestyle, Run pycodestyle check"
   echo "       --flake, Run flake check"
   echo "       <test_file_name.py>, Run test file"
   echo "To run vRouter only:"
   echo "    VROUTER_ONLY_MODE=1 ./run_test.sh"
   echo "To run vtest only:"
   echo "    VTEST_ONLY_MODE=1 ./run_test.sh <test_file_name.py>"
   echo
}

if [ -z "$vrouter_path" ]; then
   echo -n "Using default vRouter path - "
   vrouter_path=$(realpath $sb_path/debug/vrouter/dpdk/contrail-vrouter-dpdk)
   echo $vrouter_path
   if [ ! -f $vrouter_path ];
   then
       echo "vRouter path not set"
       exit -1
   fi
fi
if [ -z "$vtest_path" ]; then
   echo -n "Using default vtest path - "
   vtest_path=$(realpath $sb_path/debug/vrouter/utils/vtest/vtest)
   echo $vtest_path
   if [ ! -f $vtest_path ];
   then
       echo "vtest path not set"
       exit -1
   fi
fi
if [ -z "$socket_path" ]; then
   echo -n "Using default socket path - "
   socket_path=$(realpath $sb_path/debug/vrouter/utils/vtest_py_venv/sock_dir)
   mkdir -p $socket_path
   echo $socket_path
   if [ ! -d $socket_path ];
   then
       echo "socket path not set"
       exit -1
   fi
fi
if [ -z "$vtest_py_venv_path" ]; then
   echo -n "Using default venv path - "
   vtest_py_venv_path=$(realpath $sb_path/debug/vrouter/utils/vtest_py_venv)
   echo "$vtest_py_venv_path"
   if [ ! -d $vtest_py_venv_path ];
   then
       echo "venv path not set"
       exit -1
   fi
fi
if [ -z "$vtest_only_mode" ]; then
    vtest_only_mode=0
fi
if [ $vtest_only_mode -eq 1 ];
then
    pidof contrail-vrouter-dpdk
    if [ $? -ne 0 ];
    then
        echo
        echo "Error! You have specified vtest_only mode, but there is"
        echo "no vrouter running. Please check!"
        exit -2
    fi
fi
if [ -z "$vrouter_only_mode" ]; then
    vrouter_only_mode=0
fi

if [ \( $vrouter_only_mode -eq 0 \) -a \( $# -eq 0 \) ];
then
    Usage
    exit 0
fi 

echo "Running tests with following params:"
echo "VROUTER_DPDK_PATH: " $vrouter_path
echo "VTEST_PATH: " $vtest_path
echo "VROUTER_SOCKET_PATH: " $socket_path
echo "VTEST_PY_VENV_PATH: " $vtest_py_venv_path
echo "VTEST_ONLY_MODE: " $vtest_only_mode
echo "VROUTER_ONLY_MODE:" $vrouter_only_mode
echo "TEST PARAM: " $test_opt

if [ $vrouter_only_mode -eq 1 ];
then
    cmd="taskset 0x1 $vrouter_path --no-daemon --no-huge --vr_packet_sz 2048 --vr_socket_dir $socket_path"
    echo $cmd
    exec $cmd
    exit 0
fi

extension=$(echo "$test_opt" | cut -d'.' -f2)
if [ "$extension" == "py" ];
then
    echo "cp tests/$test_opt $vtest_py_venv_path/tests"
    cp tests/$test_opt $vtest_py_venv_path/tests
fi

echo "Entering venv"
cd $vtest_py_venv_path
source ./bin/activate

export VROUTER_DPDK_PATH=$vrouter_path
export VTEST_PATH=$vtest_path
export VROUTER_SOCKET_PATH=$socket_path
export VTEST_ONLY_MODE=$vtest_only_mode

if [ "$test_opt" == "--all" ]; then
    echo "Executing all the tests in ./tests dir .."
    pytest ./tests/*
elif [ "$test_opt" == "--pycodestyle" ]; then
    echo "Running pycodestyle check .."
    pycodestyle vtest_lib.py
    pycodestyle ./tests/*
elif [ "$test_opt" == "--flake" ]; then
    echo "Running flake check .."
    flake8 vtest_lib.py
    flake8 ./tests/*
else
    echo "Executing test file $test_opt .."
    pytest -s ./tests/$test_opt
fi

echo "Exiting venv"
deactivate


