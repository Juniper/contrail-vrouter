#!/usr/bin/python

import shutil
import os
import subprocess
import glob

if __name__ == "__main__":
    vrouter_path = os.environ['VROUTER_DPDK_PATH']
    vtest_path = os.environ['VTEST_PATH']
    socket_path = os.environ['VROUTER_SOCKET_PATH']
    socket_port = os.environ['VROUTER_SOCKET_PORT']
    vtest_py_src_path = os.environ['VTEST_PY_SRC_PATH']

    if (vtest_py_src_path is None):
        vtest_py_src_path = "."

    print "Running tests with following params:"
    print "VROUTER_DPDK_PATH: %s" %(vrouter_path)
    print "VTEST_PATH: %s" %(vtest_path)
    print "VROUTER_SOCKET_PATH: %s" %(socket_path)
    print "VROUTER_SOCKET_PORT: %s" %(socket_port)
    print "VTEST_PY_SRC_PATH: %s" %(vtest_py_src_path)

    shutil.rmtree(socket_path+"/var", ignore_errors=True)
    os.mkdir(socket_path+"/var")
    os.mkdir(socket_path+"/var/run")
    os.mkdir(socket_path+"/var/run/vrouter")

    # all tests are executed from vtest_py src path
    os.chdir(vtest_py_src_path)
    file_list = glob.glob("./tests/*.py")
    file_list.sort()
    for f in file_list:
        print "\nExecuting %s test file ============================" %(f)
        subprocess.call(f + " " + vrouter_path + " " + vtest_path + " " + \
                        socket_path + "/var/run/vrouter" + " " + socket_port \
                        ,shell=True)

