#!/bin/python

import os
from os import path
import sys
import argparse
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

    args = vars(parser.parse_args())
    test_opt = args['test']

    sb_path = os.environ['PWD'] + '/build'
    if(args['vrouter'] is None):
        path_cmd = 'realpath {}/debug/vrouter/dpdk/contrail-vrouter-dpdk'.\
            format(sb_path)
        args['vrouter'] = subprocess.check_output(path_cmd, shell=True)[:-1]
        logging.info("Using default vrouter path - {}".format(args['vrouter']))
        os.environ['VROUTER_DPDK_PATH'] = args['vrouter']
        if(path.exists(args['vrouter']) == False):
            logging.error("vRouter path not set")
            return

    if(args['vtest'] is None):
        path_cmd = 'realpath {}/debug/vrouter/utils/vtest/vtest'.format(
            sb_path)
        args['vtest'] = subprocess.check_output(path_cmd, shell=True)[:-1]
        logging.info("Using default vtest path - {}".format(args['vtest']))
        os.environ['VTEST_PATH'] = args['vtest']
        if(path.exists(args['vtest']) == False):
            logging.error("vtest path not set")
            return

    if(args['socket'] is None):
        path_cmd = \
            'realpath {}/debug/vrouter/utils/vtest_py_venv/var/run/vrouter'.\
            format(sb_path)
        args['socket'] = subprocess.check_output(path_cmd, shell=True)[:-1]
        logging.info("Using default socket path - {}".format(args['socket']))
        os.environ['VROUTER_SOCKET_PATH'] = args['socket']
        if(path.exists(args['socket']) == False):
            logging.error("socket path not set")
            return

    if(args['venv'] is None):
        path_cmd = 'realpath {}/debug/vrouter/utils/vtest_py_venv'.format(
            sb_path)
        args['venv'] = subprocess.check_output(path_cmd, shell=True)[:-1]
        logging.info(
            "Using default venv path - {}".format(args['venv']))
        os.environ['VTEST_PY_VENV_PATH'] = args['venv']
        if(path.exists(args['venv']) == False):
            logging.error("venv path not set")
            return

    vif_utilily_path = sb_path + '/debug/vrouter/utils/'
    if(args['cli'] == 'vif --list'):
        cmd = '{}{} --sock-dir {}'.format(vif_utilily_path, args['cli'],
                                          args['socket'])
        os.system(cmd)
        return

    logging.info("\nRunning tests with following params:")
    logging.info("VROUTER_DPDK_PATH: {}".format(args['vrouter']))
    logging.info("VTEST_PATH: {}".format(args['vtest']))
    logging.info("VROUTER_SOCKET_PATH: {}".format(args['socket']))
    logging.info("VTEST_PY_VENV_PATH: {}".format(args['venv']))
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
                --vr_socket_dir {}'.format(args['vrouter'], args['socket'])
        logging.info("Running cmd {}".format(exec_cmd))
        os.execlp("taskset", "taskset", "0x6", args['vrouter'],
                  "--no-daemon", "--no-huge", "--vr_packet_sz",
                  "2048", "--vr_socket_dir", args['socket'])
        return
    else:
        os.environ["VROUTER_ONLY_MODE"] = "0"

    extension = None
    if(test_opt is not None and test_opt.find('.py') != -1):
        extension = test_opt.split('.')[1]
    if(extension == 'py'):
        cmd = "cp tests/{} {}/tests".format(test_opt,
                                            args['venv'])
        logging.info("Running cmd {}".format(cmd))
        os.system(cmd)

    logging.info("Entering venv")
    os.chdir(args['venv'])
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
