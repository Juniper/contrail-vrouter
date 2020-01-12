#
# Copyright (c) 2019 Juniper Networks, Inc. All rights reserved.
#

import os
import time
import logging
import signal
import shutil
import subprocess

from vr_py_sandesh.vr_py.ttypes import *
from pysandesh.transport.TTransport import *
from pysandesh.protocol.TProtocol import *
from pysandesh.protocol.TXMLProtocol import *
import xml.etree.ElementTree as ET
from scapy.all import *

logging.basicConfig(filename='vtest_py.log',
                    filemode='w',
                    level=logging.DEBUG,
                    format='%(asctime)s %(message)s')


class TestCase(object):
    auto_cleanup = False
    def __init__(self, *args, **kwargs):
        super(TestCase, self).__init__(*args, **kwargs)
        self._auto_cleanup = False

    @classmethod
    def setUpClass(cls):
        super(TestCase, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TestCase, cls).setUpClass()

    def setUp(self):
        super(TestCase, self).setUp()
        logging.info("Running %s" % (self.id()))

    def tearDown(self):
        super(TestCase, self).tearDown()

# Need to have functionality to start/stop vrouter and vtest


class VTestBase(TestCase):
    VT_SANDESH_CMD = 0
    VT_RESPONSE_NOTREQD = 0
    VT_RESPONSE_REQD = 1
    vr_args = {}
    vt_args = {}
    test_name = None
    sreq_num = 0
    pid = 0

    def __init__(self, *args, **kwargs):
        super(VTestBase, self).__init__(*args, **kwargs)
        self.sreq_class = None

    @classmethod
    def setUpClass(cls):
        logging.info("Launching vrouter instance")
        cls.vr_args = cls.get_vrouter_args()
        cls.launch_vrouter_instance()

    @classmethod
    def tearDownClass(cls):
        logging.info("Killing vrouter instance")
        cls.kill_vrouter_instance()

    @classmethod
    def setUp(cls, test):
        cls.test_name = test.__name__
        cls.vtest_ut_init()

    @classmethod
    def tearDown(cls):
        # cls.vtest_ut_cleanup()
        pass

    @classmethod
    def get_vrouter_args(cls):
        vr_args = {}
        vr_args['vrouter_path'] = os.environ['VROUTER_DPDK_PATH']
        vr_args['socket_dir'] = os.environ['VROUTER_SOCKET_PATH']
        vr_args['vtest_only'] = int(os.environ['VTEST_ONLY_MODE'])
        vr_args['taskset'] = '0x6'
        return vr_args

    @classmethod
    def launch_vrouter_instance(cls):
        # Add code to start vrouter
        if (cls.vr_args['vtest_only']):
            print("VTEST_ONLY_RETURN " + str(cls.vr_args['vtest_only']))
            return
        cpid = os.fork()
        print(os.getcwd())
        if cpid == 0:
            os.execlp("taskset", "taskset", cls.vr_args['taskset'],
                      cls.vr_args['vrouter_path'], "--no-daemon", "--no-huge",
                      "--vr_packet_sz", "2048", "--vr_socket_dir",
                      cls.vr_args['socket_dir'])
        else:
            print("Running cmd - taskset %s %s --no-daemon --no-huge "
                  "--vr_packet_sz 2048 --vr_socket_dir %s"
                  % (cls.vr_args['taskset'], cls.vr_args['vrouter_path'],
                     cls.vr_args['socket_dir']))
            print("pid = " + str(cpid))
            cls.pid = cpid
            count = 0
            ret = 0
            while (count < 10):
                cmd = "lsof " + cls.vr_args['socket_dir'] +\
                    "/dpdk_netlink | wc -l"
                print "Running cmd - ", cmd
                try:
                    ret = subprocess.check_output(cmd, shell=True)
                    # check if the netlink is up using the ret value
                    if (ret == "2\n"):
                        break
                    else:
                        time.sleep(1)
                        count += 1
                except Exception as e:
                    print e
                    time.sleep(1)
                    count += 1
            if (ret != "2\n"):
                print "Failed to bringup vrouter"
                return -1
            else:
                return 0

    @classmethod
    def kill_vrouter_instance(cls):
        # Stop vrouter
        if (cls.vr_args['vtest_only']):
            print "Stopping vrouter pid=" + str(cls.pid)
        if (cls.pid > 0):
            try:
                os.kill(cls.pid, signal.SIGKILL)
            except OSError as e:
                print e

    @classmethod
    def get_test_file_path(self):
        xml_file_path_prefix = "./tests/"
        return xml_file_path_prefix + self.test_name + "_data/"

    @classmethod
    def vtest_ut_init(cls):
        # Prepare vtest, cleanup temp files, create new UT directory etc.
        cls.vt_args['vtest_binary_path'] = os.environ['VTEST_PATH']
        cls.vt_args['socket_dir'] = os.environ['VROUTER_SOCKET_PATH']
        shutil.rmtree(cls.get_test_file_path(), ignore_errors=True)
        try:
            os.mkdir(cls.get_test_file_path())
        except OSError as e:
            print e

    @classmethod
    def vtest_ut_cleanup(cls):
        shutil.rmtree(cls.get_test_file_path(), ignore_errors=True)

    # api to get next sandesh req number
    def get_sandesh_req_num(self):
        VTestBase.sreq_num += 1
        return VTestBase.sreq_num

    # replace sandesh obj name in xml file generated
    # as pysandesh uses the derived class name to write the req;
    # eg: vif instead of vr_interface_req as vif is derived from
    # vr_interface_req
    @staticmethod
    def replace_sandesh_obj_name(obj, file):
        obj_class_name = obj.__class__.__name__
        if hasattr(obj, 'sreq_class'):
            print "Replacing " + obj_class_name + " with " + obj.sreq_class
            try:
                subprocess.call("sed -i 's/" + obj_class_name + "/" +
                                obj.sreq_class + "/g' " + file, shell=True)
            except Exception as e:
                print "Failed to replace sandesh obj name = ", obj_class_name
                print e

    # create xml proto with file handle
    @staticmethod
    def get_xml_proto_file_handle(filehandle):
        ft = TFileObjectTransport(filehandle)
        xml_proto = TXMLProtocolFactory().getProtocol(ft)
        return xml_proto

    # creates a sandesh req in xml file format
    def create_sandesh_req(self, obj, filename):
        msghdr = "<?xml version=\"1.0\"?><test><test_name> " + \
                 "sandesh req</test_name><message>"
        msgfooter = "</message></test>"
        # open the file
        with open(filename, 'w') as fh:
            try:
                # write msg hdr
                fh.write(msghdr)
                # write sandesh xml output of the obj
                obj.write(self.get_xml_proto_file_handle(fh))
                fh.write(msgfooter)
            except Exception as e:
                print "Failedddd to write sandesh req file"
                print e
        try:
            self.replace_sandesh_obj_name(obj, filename)
            subprocess.call("xmllint --format " + filename +
                            " --output " + filename, shell=True)
        except Exception as e:
            print "Faileddddd to format xml output"
            print e

    def parse_xml_field(self, file, field_name):

        tree = ET.parse(file)
        elem = tree.getroot().find(field_name)
        if (elem.find("list") is not None):
            return elem.find("list").text
        else:
            return elem.text

    def send_sandesh_req(self, obj_list, get_resp=VT_RESPONSE_NOTREQD):
        obj_list_internal = []
        if (isinstance(self, list)):
            obj_list_internal = obj_list
        else:
            obj_list_internal = [obj_list]
        resp = []
        for obj in obj_list_internal:
            # create the req xml file
            filename = self.get_test_file_path() + self.test_name \
                + "_" + self.__class__.__name__ + "_" + \
                str(self.get_sandesh_req_num())
            req_filename = filename + "_req.xml"
            resp_filename = ""
            self.create_sandesh_req(obj, req_filename)
            # run the vtest cmd
            if (get_resp == self.VT_RESPONSE_REQD):
                resp_filename = filename + "_resp.xml"
            self.run_vtest_command(self.VT_SANDESH_CMD, req_filename,
                                   resp_filename)
            resp.append(resp_filename)
        if (isinstance(self, list)):
            return resp
        else:
            return resp[0]

    @staticmethod
    def create_pcap_req(input_pkt_list, input_if_idx,
                        output_pkt_list, output_if_idx, req_file):
        # create the pcap files first
        inp_pcap_filename = req_file + ".input.pcap"
        wrpcap(inp_pcap_filename, input_pkt_list)
        inp_pcap_filestr_list = inp_pcap_filename.split("/")
        inp_pcap_filestr = inp_pcap_filestr_list[len(
            inp_pcap_filestr_list) - 1]
        if (output_pkt_list is not None):
            out_pcap_filename = req_file + ".output.pcap"
            wrpcap(out_pcap_filename, output_pkt_list)
            out_pcap_filestr_list = out_pcap_filename.split("/")
            out_pcap_filestr = \
                out_pcap_filestr_list[len(out_pcap_filestr_list) - 1]

        # write the request file now
        hdr = "<?xml version=\"1.0\"?><test><test_name> \
               pkt test</test_name><packet>"
        footer = "</packet></test>"

        with open(req_file, 'w') as fh:
            try:
                fh.write(hdr)
                fh.write("<pcap_input_file>" + inp_pcap_filestr +
                         "</pcap_input_file>\n")
                if (output_pkt_list is not None):
                    fh.write("<pcap_expected_file>" + out_pcap_filestr
                             + "</pcap_expected_file>\n")
                fh.write("<tx_interface> <vif_index>" + input_if_idx
                         + "</vif_index></tx_interface>\n")
                if (output_pkt_list is not None):
                    fh.write("<rx_interface> <vif_index>" + output_if_idx +
                             "</vif_index> </rx_interface>\n")
                fh.write(footer)
            except Exception as e:
                print "Failed to write pcap req file"
                print e
        try:
            subprocess.call("xmllint --format " + req_file +
                            " --output " + req_file, shell=True)
        except Exception as e:
            print e
            print "Failed to format xml output"

    def run_vtest_command(self, is_pkt_cmd, arg1, arg2=""):
        cmd = self.vt_args['vtest_binary_path'] + " --vr_socket_dir " + \
            self.vt_args['socket_dir']
        if (is_pkt_cmd == 0):
            cmd += " --send_sandesh_req " + arg1
            if (arg2):
                cmd += " --recv_sandesh_resp " + arg2
        else:
            cmd += " --send_recv_pkt " + arg1
        print "Running cmd ", cmd
        try:
            ret = self.run_command(cmd)
        except Exception as err:
            print "Failed to run vtest cmd: " + cmd
            print "Error : %s " % err
            return -1

    # Generic run command
    def run_command(self, cmd):
        return os.popen(cmd).read()
