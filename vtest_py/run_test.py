#!/bin/bash

import os
import os.path
from os import path
import sys
import argparse
import subprocess as sp
import py
import pytest

vrouter_path = ""
vtest_path = ""
socket_path = ""
vtest_py_venv_path = ""
vtest_only_mode = 0
vrouter_only_mode = 0
test_opt = ""
sb_path = os.environ['PWD'] + '/../../build'

def Usage():
    print "Usage: python run_test.py [options]"
    print "       --all , Run all tests"
    print "        --pycodestyle, Run pycodestyle check"
    print "       <test_file_name.py>, Run test file"

def parse(cmd):
    test_opt = cmd[1]
    ap = argparse.ArgumentParser()

    ap.add_argument('-vr', '--vrouter_path', required=False)
    ap.add_argument('-vt', '--vtest_path', required=False)
    ap.add_argument('-sp', '--socket_path', required=False)
    ap.add_argument('-venp', '--vtest_py_venv_path', required=False)
    ap.add_argument('-vt_only', '--vtest_only_mode', required=False)
    ap.add_argument('-vr_only', '--vrouter_only_mode', required=False)
    ap.add_argument('-test', '--test_file', required=False)   
    ap.add_argument('-gxml', '--xml', required=False)  
 
    args = vars(ap.parse_args())
    test_opt = args['test_file']
    if(args['vrouter_only_mode'] != None):
        vrouter_only_mode = int(args['vrouter_only_mode'])
    else:
        vrouter_only_mode = 0
    if(args['vtest_only_mode'] != None):
        vtest_only_mode = int(args['vtest_only_mode'])
    else:
        vtest_only_mode = 0
    if(args['vrouter_path'] == None):
        print "Using default vrouter path - "
        path_cmd = 'realpath {}/debug/vrouter/dpdk/contrail-vrouter-dpdk'.format(sb_path)
        vrouter_path = sp.check_output(path_cmd, shell=True)[:-1]
        print vrouter_path
        if(path.exists(vrouter_path)== False):
            print "vRouter path not set"
            return -1
    
    if(args['vtest_path'] == None):
        print "Using default vtest path - "
        path_cmd = 'realpath {}/debug/vrouter/utils/vtest/vtest'.format(sb_path)
        vtest_path = sp.check_output(path_cmd, shell=True)[:-1]
        print vtest_path
        if(path.exists(vtest_path) == False):
            print "vtest path not set"
            return -1
    
    if(args['socket_path'] == None):
        print "Using default socket path - "
        path_cmd = 'realpath {}/debug/vrouter/utils/vtest_py_venv/var/run/vrouter'.format(sb_path)
        socket_path = sp.check_output(path_cmd, shell=True)[:-1]
        print socket_path
        if(path.exists(socket_path) == False):
            print "socket path not set"
            return -1

    if(args['vtest_py_venv_path'] == None):
        print "Using default venv path - "
        path_cmd = 'realpath {}/debug/vrouter/utils/vtest_py_venv'.format(sb_path)
        vtest_py_venv_path = sp.check_output(path_cmd, shell=True)[:-1]
        print vtest_py_venv_path
        if(path.exists(vtest_py_venv_path) == False):
            print "venv path not set"
            return -1

    if(vtest_only_mode == 1):
        if(sp.check_output(['pidof', 'contrail-vrouter-dpdk']) == 0):
            print "Error! You have specified vtest_only_mode, but there is"
            print "no vrouter running. Please check!"
            return -2
    
    if(vrouter_only_mode == 0 and len(cmd) == 0):
        Usage()
        return 0
    
    print "Running tests with following params:"
    print "VROUTER_DPDK_PATH: ", vrouter_path
    print "VTEST_PATH: ", vtest_path
    print "VROUTER_SOCKET_PATH: ", socket_path
    print "VTEST_PY_VENV_PATH: ", vtest_py_venv_path
    print "VTEST_ONLY_MODE: ", vtest_only_mode
    print "VROUTER_ONLY_MODE: ", vrouter_only_mode
    print "TEST PARAM: ", test_opt

    if(vrouter_only_mode == 1):
        exec_cmd = 'taskset 0x1 {} --no-daemon --no-huge --vr_packet_sz 2048 --vr_socker_dir {}'.format(vrouter_path, socket_path)
        print exec_cmd
        os.execlp("taskset", "taskset", "0x1", vrouter_path,
                      "--no-daemon", "--no-huge", "--vr_packet_sz",
                      "2048", "--vr_socket_dir", socket_path)
        return 0
    print test_opt
    extension = ""
    if(test_opt != None and test_opt.find('.py') != -1):
        extension = test_opt.split('.')[1]
    if(extension == 'py'):
        print "cp /root/contrail/vrouter/tests/{} {}/tests".format(test_opt, vtest_py_venv_path)
        os.system('cp /root/contrail/vrouter/tests/{} {}/tests'.format(test_opt, vtest_py_venv_path))
    
    print "Entering venv" 
    os.chdir('/root/contrail/build/debug/vrouter/utils/vtest_py_venv')
    os.system('source ./bin/activate')

    result = 0
    if(test_opt == 'all'):
        print("Executing all the tests in ./tests dir ..")
        if(args['xml'] != None):
             result = pytest.main('./tests --junitxml=result.xml')
        else:
             result = pytest.main('./tests/')
    elif(test_opt == "--pycodestyle"):
        sp.check_output('pycodestyle vtest_lib.py')
        sp.check_output('pycodestyle ./tests/*')
    elif(test_opt == '--flake'):
        print("Running flake check ..")
        sp.check_output('flake8 vtest_lib.py')
        sp.check_output('flake8 ./tests/*')
    else:
        if(test_opt != None):
            print "Executing test file %s ..", test_opt
            if(args['xml'] != None):
                pytest.main('-s ./tests/{} --junitxml=result.xml'.format(test_opt))
            else:
                pytest.main('-s ./tests/{}'.format(test_opt))
    
    print("Exiting venv")
    os.system('deactivate')

    if(result != 0):
        print("Script execution failed")
        return 1
    else:
        return 0

def main():
    cmd = sys.argv
    parse(cmd)

if __name__ == '__main__':
    main()
    

