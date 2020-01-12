#!/bin/python

import os
from os import path
import sys
import argparse
import platform
import subprocess
import logging

logging.basicConfig(filename='vtest_py.log',
                    filemode='w',
                    level=logging.DEBUG,
                    format='%(asctime)s %(message)s')


def parse(cmd):

    if (len(cmd) == 1):
        print("Use -h or --help option for usage detail")
        return

    parser = argparse.ArgumentParser()
    parser.add_argument('-vr', '--vrouter', required=False,
                        help="Specify vrouter path")
    parser.add_argument('-vt', '--vtest', required=False,
                        help="specify vtest path")
    parser.add_argument('-sp', '--socket', required=False,
                        help="specify socket path")
    parser.add_argument('-v', '--venv', required=False,
                        help="specify vtest_py venv path")
    parser.add_argument('-vt_only', '--vtest_only',
                        help="run vTest alone", action="store_true")
    parser.add_argument('-vr_only', '--vrouter_only',
                        help="run vRouter alone", action="store_true")
    parser.add_argument('-t', '--test', required=False,
                        help="test a specific file")
    parser.add_argument('-gxml', '--xml', required=False,
                        help="tpecify xml file")
    parser.add_argument("-a", "--all",
                        help="run all tests", action="store_true")
    parser.add_argument("-p", "--pycodestyle",
                        help="run pycodestyle check", action="store_true")
    parser.add_argument("-f", "--flake",
                        help="run flake check", action="store_true")
    parser.add_argument("-c", "--cli", required=False,
                        help="run vrouter commands like 'vif --list', etc")

    vrouter_path = os.environ.get('VROUTER_DPDK_PATH')
    vtest_path = os.environ.get('VTEST_PATH')
    socket_path = os.environ.get('VROUTER_SOCKET_PATH')
    vtest_py_venv_path = os.environ.get('VTEST_PY_VENV_PATH')
    sb_path = os.environ.get('PWD') + '/../../build'

    args = vars(parser.parse_args())
    test_opt = args['test']

    if args['vrouter'] is None:
        if vrouter_path is None:
            path_cmd = 'realpath {}/debug/vrouter/dpdk/contrail-vrouter-dpdk'.\
                format(sb_path)
            vrouter_path = subprocess.check_output(path_cmd, shell=True)[:-1]
        logging.info("Using default vrouter path - {}".format(vrouter_path))
    else:
        vrouter_path = args['vrouter']
    if not path.exists(vrouter_path):
        logging.error("vRouter path not set")
        return
    os.environ['VROUTER_DPDK_PATH'] = vrouter_path

    if args['vtest'] is None:
        if vtest_path is None:
            path_cmd = 'realpath {}/debug/vrouter/utils/vtest/vtest'.format(
                sb_path)
            vtest_path = subprocess.check_output(path_cmd, shell=True)[:-1]
        logging.info("Using default vtest path - {}".format(vtest_path))
    else:
        vtest_path = args['vtest']
    if not path.exists(vtest_path):
        logging.error("vtest path not set")
        return
    os.environ['VTEST_PATH'] = vtest_path

    if args['socket'] is None:
        if socket_path is None:
            path_cmd = \
                'realpath {}/debug/vrouter/utils/vtest_py_venv/var/run/vrouter'.\
                format(sb_path)
            socket_path = subprocess.check_output(path_cmd, shell=True)[:-1]
        logging.info("Using default socket path - {}".format(vtest_path))
    else:
        socket_path = args['socket']
    if not path.exists(socket_path):
        logging.error("socket path not set")
        return
    os.environ['VROUTER_SOCKET_PATH'] = socket_path

    if args['venv'] is None:
        if vtest_py_venv_path is None:
            path_cmd = 'realpath {}/debug/vrouter/utils/vtest_py_venv'.format(
                sb_path)
            vtest_py_venv_path = \
                subprocess.check_output(path_cmd, shell=True)[:-1]
        logging.info("Using default venv path - {}".format(args['venv']))
    else:
        vtest_py_venv_path = args['venv']
    if not path.exists(vtest_py_venv_path):
        logging.error("venv path not set")
        return
    os.environ['VTEST_PY_VENV_PATH'] = vtest_py_venv_path

    vif_utilily_path = sb_path + '/debug/vrouter/utils/'
    if(args['cli'] == 'vif --list'):
        cmd = '{}{} --sock-dir {}'.format(vif_utilily_path, args['cli'],
                                          socket_path)
        os.system(cmd)
        return

    logging.info("\nRunning tests with following params:")
    logging.info("VROUTER_DPDK_PATH: {}".format(vrouter_path))
    logging.info("VTEST_PATH: {}".format(vtest_path))
    logging.info("VROUTER_SOCKET_PATH: {}".format(socket_path))
    logging.info("VTEST_PY_VENV_PATH: {}".format(vtest_py_venv_path))
    logging.info("VTEST_ONLY_MODE: {}".format(args['vtest_only']))
    logging.info("VROUTER_ONLY_MODE: {}".format(args['vrouter_only']))
    logging.info("TEST PARAM: {}".format(test_opt))

    if args['vtest_only']:
        os.environ["VTEST_ONLY_MODE"] = "1"
        if(os.system('pidof contrail-vrouter-dpdk') != 0):
            print("Error! You have specified vtest_only, but there is")
            print("no vrouter running. Please check!")
            return
    else:
        os.environ["VTEST_ONLY_MODE"] = "0"

    if args['vrouter_only']:
        os.environ["VROUTER_ONLY_MODE"] = "1"
        exec_cmd = 'taskset 0x6 {} --no-daemon --no-huge --vr_packet_sz 2048 \
                --vr_socket_dir {}'.format(vrouter_path, socket_path)
        logging.info("Running cmd {}".format(exec_cmd))
        os.execlp("taskset", "taskset", "0x6", vrouter_path,
                  "--no-daemon", "--no-huge", "--vr_packet_sz",
                  "2048", "--vr_socket_dir", socket_path)
        return
    else:
        os.environ["VROUTER_ONLY_MODE"] = "0"

    extension = None
    if(test_opt is not None and test_opt.find('.py') != -1):
        extension = test_opt.split('.')[1]
    if(extension == 'py'):
        cmd = "cp {} {}/tests".format(test_opt, vtest_py_venv_path)
        logging.info("Running cmd {}".format(cmd))
        os.system(cmd)

    logging.info("Entering venv")
    os.chdir(vtest_py_venv_path)
    result = 0
    cmd = None
    if args['all']:
        logging.info("Executing all the tests in ./tests dir ..")
        if(args['xml'] is not None):
            cmd = 'pytest ./tests --junitxml=result.xml'
        else:
            cmd = 'pytest ./tests/'
    elif args['pycodestyle']:
        logging.info("Running pycodestyle check ..")
        cmd = 'pycodestyle ./lib/vtest* ./tests/*'
    elif args['flake']:
        logging.info("Running flake check ..")
        cmd = 'flake8 ./lib/vtest* ./tests/*'
    else:
        if(test_opt is not None):
            logging.info("Executing test file %s ..".format(test_opt))
            if(args['xml'] is not None):
                cmd = 'pytest -s ./tests/{} --junitxml=result.xml'.format(
                    test_opt)
            else:
                cmd = 'pytest -s ./tests/{}'.format(test_opt)
    run_command(cmd)
    logging.info("Exiting venv")

    if(result != 0):
        logging.error("Script execution failed")
        return


def run_command(cmd):
    if(cmd is None):
        logging.info("No command to run. Exiting!!!")
        return
    logging.info("Running cmd - {}".format(cmd))
    cmd = "source ./bin/activate;" + cmd + "; deactivate"
    os.system(cmd)


def main():
    cmd = sys.argv
    parse(cmd)


if __name__ == '__main__':
    main()
