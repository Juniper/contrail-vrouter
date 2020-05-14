#!/bin/python

import os
from os import path
import sys
import argparse
import platform
import subprocess
import logging
import xml.etree.ElementTree as ET

logfile = None
if os.environ.get('VTEST_PY_VENV_PATH'):
    logfile = os.environ['VTEST_PY_VENV_PATH'] + '/run_test.log'
else:
    logfile = os.path.realpath(
        os.environ.get('PWD') +
        '/../../build/debug/vrouter/utils/vtest_py_venv/run_test.log')
logging.basicConfig(filename=logfile,
                    filemode='w',
                    level=logging.DEBUG,
                    format='%(asctime)s %(message)s')


def parse(cmd):

    if (len(cmd) == 1):
        print("Use -h or --help option for usage detail")
        return

    parser = argparse.ArgumentParser()
    parser.add_argument('-vr', '--vrouter', required=False,
                        help="specify vrouter path")
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
    parser.add_argument('-gxml', '--xml',
                        help="tpecify xml file", action="store_true")
    parser.add_argument("-a", "--all",
                        help="run all tests", action="store_true")
    parser.add_argument("-p", "--pycodestyle",
                        help="run pycodestyle check", action="store_true")
    parser.add_argument("-f", "--flake",
                        help="run flake check", action="store_true")
    parser.add_argument("-c", "--cli", required=False,
                        help="run vrouter commands like 'vif --list'"
                        "'flow -l', etc")
    parser.add_argument("-l", "--log_level", required=False,
                        help="set log level (ERROR/INFO/DEBUG)",
                        default='INFO')

    vrouter_path = os.environ.get('VROUTER_DPDK_PATH')
    vtest_path = os.environ.get('VTEST_PATH')
    socket_path = os.environ.get('VROUTER_SOCKET_PATH')
    vtest_py_venv_path = os.environ.get('VTEST_PY_VENV_PATH')
    tests_path = os.environ.get('PWD')
    build_path = tests_path + '/../../build'

    args = vars(parser.parse_args())
    test_opt = args['test']

    if args['vrouter'] is None:
        if vrouter_path is None:
            path_cmd = '{}/debug/vrouter/dpdk/contrail-vrouter-dpdk'.\
                format(build_path)
            vrouter_path = os.path.realpath(path_cmd)
        logging.info("Using default vrouter path - {}".format(vrouter_path))
    else:
        vrouter_path = args['vrouter']
    if not path.exists(vrouter_path):
        logging.error("vRouter path not set")
        exit(1)
    os.environ['VROUTER_DPDK_PATH'] = vrouter_path

    if args['vtest'] is None:
        if vtest_path is None:
            path_cmd = '{}/debug/vrouter/utils/vtest/vtest'.format(
                build_path)
            vtest_path = os.path.realpath(path_cmd)
        logging.info("Using default vtest path - {}".format(vtest_path))
    else:
        vtest_path = args['vtest']
    if not path.exists(vtest_path):
        logging.error("vtest path not set")
        exit(1)
    os.environ['VTEST_PATH'] = vtest_path

    if args['socket'] is None:
        if socket_path is None:
            path_cmd = '{}/debug/vrouter/utils/vtest_py_venv/sock/'.\
                format(build_path)
            socket_path = os.path.realpath(path_cmd)
        logging.info("Using default socket path - {}".format(vtest_path))
    else:
        socket_path = args['socket']
    #VR_UNIX_PATH_MAX is set as 108
    if len(socket_path) > (108 - len('dpdk_netlink')):
        logging.info("Socket path is too long {}, so setting it to /tmp/sock".\
                format(socket_path))
        if not os.path.exists('/tmp/sock'):
            os.makedirs('/tmp/sock')
        socket_path = os.path.realpath('/tmp/sock')

    if not path.exists(socket_path):
        logging.error("socket path not set")
        exit(1)
    os.environ['VROUTER_SOCKET_PATH'] = socket_path

    if args['venv'] is None:
        if vtest_py_venv_path is None:
            path_cmd = '{}/debug/vrouter/utils/vtest_py_venv'.format(
                build_path)
            vtest_py_venv_path = os.path.realpath(path_cmd)
        logging.info("Using default venv path - {}".format(args['venv']))
    else:
        vtest_py_venv_path = args['venv']
    if not path.exists(vtest_py_venv_path):
        logging.error("venv path not set")
        exit(1)
    os.environ['VTEST_PY_VENV_PATH'] = vtest_py_venv_path

    utilily_path = build_path + '/debug/vrouter/utils/'
    if args['cli']:
        cmd = '{}{} --sock-dir {}'.format(utilily_path, args['cli'],
                                          socket_path)
        os.system(cmd)
        exit(0)

    os.environ['LOG_PATH'] = logfile
    if args['log_level'] == 'ERROR':
        os.environ['LOG_LEVEL'] = "40"
    elif args['log_level'] == 'DEBUG':
        os.environ['LOG_LEVEL'] = "10"
    else:
        # default is info
        os.environ['LOG_LEVEL'] = "20"

    logging.info("\nRunning tests with following params:")
    logging.info("VROUTER_DPDK_PATH: {}".format(vrouter_path))
    logging.info("VTEST_PATH: {}".format(vtest_path))
    logging.info("VROUTER_SOCKET_PATH: {}".format(socket_path))
    logging.info("VTEST_PY_VENV_PATH: {}".format(vtest_py_venv_path))
    logging.info("VTEST_ONLY_MODE: {}".format(args['vtest_only']))
    logging.info("VROUTER_ONLY_MODE: {}".format(args['vrouter_only']))
    logging.info("TEST PARAM: {}".format(test_opt))
    logging.info("LOG_PATH: {}".format(logfile))
    logging.info("LOG_LEVEL: {}".format(args['log_level']))

    if args['vtest_only']:
        os.environ["VTEST_ONLY_MODE"] = "1"
        if(os.system('pidof contrail-vrouter-dpdk') != 0):
            print("Error! You have specified vtest_only, but there is")
            print("no vrouter running. Please check!")
            return 1
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
        return 0
    else:
        os.environ["VROUTER_ONLY_MODE"] = "0"

    extension = None
    if(test_opt is not None and test_opt.find('.py') != -1):
        extension = test_opt.split('.')[1]
        if extension is not None:
            extension = extension.split('::')[0]
    if(extension == 'py'):
        cmd = "cp {} {}/tests".\
          format(test_opt.split('::')[0], vtest_py_venv_path)
        logging.info("Running cmd {}".format(cmd))
        os.system(cmd)

    logging.info("Entering venv")
    os.chdir(vtest_py_venv_path)
    cmd = None
    if args['all']:
        logging.info("Executing all the tests in ./tests dir ..")
        if(args['xml'] is not None):
            cmd = 'pytest ./tests --junitxml=result.xml'
        else:
            cmd = 'pytest ./tests/'
    elif args['pycodestyle']:
        logging.info("Running pycodestyle check ..")
        cmd = "source ./bin/activate; pycodestyle lib/*.py tests/test_*.py;"
        cmd_op = os.popen(cmd).read()
        if cmd_op:
            print(cmd_op)
            raise NameError('pycodestyle errors')
        exit(0)
    elif args['flake']:
        logging.info("Running flake check ..")
        cmd = 'flake8 lib/*.py tests/test_*.py'
    else:
        if(test_opt):
            logging.info("Executing test file {} ..".format(test_opt))
            if(args['xml'] is not None):
                cmd = 'pytest -s ./tests/{} --junitxml=result.xml'.format(
                    test_opt)
            else:
                cmd = 'pytest -s ./tests/{}'.format(test_opt)
    result = run_command(cmd)
    logging.info("Exiting venv\n")

    print('Logs path : {}'.format(logfile))
    if(result != 0):
        logging.error("Script execution failed")
        exit(1)


def run_command(cmd):
    if(cmd is None):
        logging.info("No command to run. Exiting!!!")
        return 1
    logging.info("Running cmd - {}".format(cmd))
    try:
        cmd = "source ./bin/activate;" + cmd + "; deactivate"
        os.system(cmd)
    except Exception as e:
        logging.info("Running cmd - {} failed".format(cmd))
        return 1
    else:
        return 0

def parse_result():
    if not path.exists('result.xml'):
        exit(0)

    tree = ET.parse('result.xml')
    root = tree.getroot()
    for child in root:
        if child.attrib['failures'] != '0':
            print("Script execution failed")
            exit(1)

def main():
    cmd = sys.argv
    parse(cmd)
    parse_result()

if __name__ == '__main__':
    main()
