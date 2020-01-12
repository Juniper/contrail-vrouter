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

logging.basicConfig(filename=os.environ['LOG_PATH'],
                    filemode='a',
                    level=int(os.environ['LOG_LEVEL']),
                    format='%(asctime)s %(message)s')


class TestCase(object):
    # set auto_cleanup for auto deletion of objects
    # during teardown
    auto_cleanup = False
    logger = logging

    def __init__(self, *args, **kwargs):
        super(TestCase, self).__init__(*args, **kwargs)

    @classmethod
    def setUpClass(self):
        super(TestCase, self).setUpClass()

    @classmethod
    def tearDownClass(self):
        super(TestCase, self).setUpClass()

    def setUp(self):
        super(TestCase, self).setUp()
        self.logger.info("Running %s" % (self.id()))

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
        self.input_pcap_file = None
        self.output_pcap_file = None

    @classmethod
    def setUpClass(self):
        self.logger.info("\n")
        self.logger.info("Launching vrouter instance")
        self.vr_args = self.get_vrouter_args()
        self.launch_vrouter_instance()

    @classmethod
    def tearDownClass(self):
        self.logger.info("Killing vrouter instance")
        self.kill_vrouter_instance()

    @classmethod
    def setUp(self, test):
        self.test_name = test.__name__
        self.vtest_ut_init()

    @classmethod
    def tearDown(self):
        VTestBase.sreq_num = 0

    @classmethod
    def get_vrouter_args(self):
        vr_args = {}
        vr_args['vrouter_path'] = os.environ['VROUTER_DPDK_PATH']
        vr_args['socket_dir'] = os.environ['VROUTER_SOCKET_PATH']
        vr_args['vtest_only'] = int(os.environ['VTEST_ONLY_MODE'])
        vr_args['taskset'] = '0x6'
        return vr_args

    @classmethod
    def launch_vrouter_instance(self):
        # Add code to start vrouter
        if (self.vr_args['vtest_only']):
            self.logger.info("VTEST_ONLY_RETURN " + str(self.vr_args['vtest_only']))
            return
        cpid = os.fork()
        if cpid == 0:
            os.execlp("taskset", "taskset", self.vr_args['taskset'],
                      self.vr_args['vrouter_path'], "--no-daemon", "--no-huge",
                      "--vr_packet_sz", "2048", "--vr_socket_dir",
                      self.vr_args['socket_dir'])
        else:
            self.logger.info("Running cmd - taskset %s %s --no-daemon --no-huge "
                  "--vr_packet_sz 2048 --vr_socket_dir %s"
                  % (self.vr_args['taskset'], self.vr_args['vrouter_path'],
                     self.vr_args['socket_dir']))
            self.logger.info("pid = " + str(cpid))
            self.pid = cpid
            count = 0
            ret = 0
            while (count < 10):
                cmd = "lsof " + self.vr_args['socket_dir'] +\
                    "/dpdk_netlink | wc -l"
                self.logger.info("Running cmd - {}".format(cmd))
                try:
                    ret = subprocess.check_output(cmd, shell=True)
                    # check if the netlink is up using the ret value
                    if (ret == "2\n"):
                        break
                    else:
                        time.sleep(1)
                        count += 1
                except Exception as e:
                    self.logger.error(e)
                    time.sleep(1)
                    count += 1
            if (ret != "2\n"):
                self.logger.error("Failed to bringup vrouter")
                return -1
            else:
                return 0

    @classmethod
    def kill_vrouter_instance(self):
        # Stop vrouter
        if (self.vr_args['vtest_only']):
            self.logger.info("Stopping vrouter pid=" + str(self.pid))
        if (self.pid > 0):
            try:
                os.kill(self.pid, signal.SIGKILL)
            except OSError as e:
                self.logger.error(e)

    @classmethod
    def get_test_file_path(self):
        xml_file_path_prefix = "./tests/"
        return xml_file_path_prefix + self.test_name + "_data/"

    @classmethod
    def get_req_file_name(self):
        # create the req xml file first
        filename = self.get_test_file_path() + self.test_name \
            + "_" + str(self.get_sandesh_req_num())
        req_filename = filename + "_req.xml"
        return req_filename

    @classmethod
    def vtest_ut_init(self):
        # Prepare vtest, cleanup temp files, create new UT directory etc.
        self.vt_args['vtest_binary_path'] = os.environ['VTEST_PATH']
        self.vt_args['socket_dir'] = os.environ['VROUTER_SOCKET_PATH']
        shutil.rmtree(self.get_test_file_path(), ignore_errors=True)
        try:
            os.mkdir(self.get_test_file_path())
        except OSError as e:
            self.logger.error(e)

    @classmethod
    def vtest_ut_cleanup(self):
        shutil.rmtree(self.get_test_file_path(), ignore_errors=True)

    # api to get next sandesh req number
    @classmethod
    def get_sandesh_req_num(self):
        VTestBase.sreq_num += 1
        return VTestBase.sreq_num

    # replace sandesh obj name in xml file generated
    # as pysandesh uses the derived class name to write the req;
    # eg: vif instead of vr_interface_req as vif is derived from
    # vr_interface_req
    def replace_sandesh_obj_name(self, obj, file):
        obj_class_name = obj.__class__.__name__
        if hasattr(obj, 'sreq_class'):
            try:
                subprocess.call("sed -i 's/" + obj_class_name + "/" +
                                obj.sreq_class + "/g' " + file, shell=True)
            except Exception as e:
                self.logger.error("Failed to replace sandesh obj name = " + obj_class_name)
                self.logger.error(e)

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
                self.logger.info("Failed to write sandesh req file")
                self.logger.info(e)
        try:
            self.replace_sandesh_obj_name(obj, filename)
            subprocess.call("xmllint --format " + filename +
                            " --output " + filename, shell=True)
        except Exception as e:
            self.logger.error("Failed to format xml output")

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
                            + "_" + str(self.get_sandesh_req_num())
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

    def create_pcap_req(self, input_pkt_list, input_if_idx,
                        output_pkt_list, output_if_idx):
        req_file = self.get_req_file_name()
        # create the pcap files first
        self.input_pcap_file = req_file + ".input.pcap"
        wrpcap(self.input_pcap_file, input_pkt_list)
        inp_pcap_filestr_list = self.input_pcap_file.split("/")
        inp_pcap_filestr = inp_pcap_filestr_list[len(
            inp_pcap_filestr_list) - 1]
        if (output_pkt_list is not None):
            self.output_pcap_file = req_file + ".output.pcap"
            wrpcap(self.output_pcap_file, output_pkt_list)
            out_pcap_filestr_list = self.output_pcap_file.split("/")
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
                self.logger.error("Failed to write pcap req file")
                self.logger.error(e)
                return None
        try:
            subprocess.call("xmllint --format " + req_file +
                            " --output " + req_file, shell=True)
        except Exception as e:
            self.logger.error(e)
            self.logger.error("Failed to format xml output")
            return None
        return req_file

    def get_output_pcap_file(self, req_file):
        # run vtest cmd which will generate output pcap file
        # and return that file
        self.run_vtest_command(True, req_file)
        return self.output_pcap_file



    def run_vtest_command(self, is_pkt_cmd, req_file, res_file=""):
        cmd = self.vt_args['vtest_binary_path'] + " --vr_socket_dir " + \
            self.vt_args['socket_dir']
        if (is_pkt_cmd == 0):
            cmd += " --send_sandesh_req " + req_file
            if (res_file):
                cmd += " --recv_sandesh_resp " + res_file
        else:
            cmd += " --send_recv_pkt " + req_file
        self.logger.info("Running cmd " + cmd)
        try:
            ret = self.run_command(cmd)
        except Exception as err:
            self.logger.error("Failed to run vtest cmd: " + cmd)
            self.logger.error("Error : %s ".format(err))
            return -1

    # Generic run command
    def run_command(self, cmd):
        return os.popen(cmd).read()
