#!/usr/bin/python

import subprocess
import time
import os
import shutil
import signal
from enum import IntEnum

from vr_py_sandesh.vr_py.ttypes import *
from pysandesh.transport.TTransport import *
from pysandesh.protocol.TProtocol import *
from pysandesh.protocol.TXMLProtocol import *

import xml.etree.ElementTree as ET
from scapy.all import *
import pytest


############################################
# Sandesh enums
############################################
class sandeshenum(IntEnum):
    """Class for sandesh enums"""

    SANDESH_OPER_ADD = 0
    SANDESH_OPER_GET = 1
    SANDESH_OPER_DEL = 2

    SANDESH_FLOW_OPER_SET = 0
    SANDESH_FLOW_OPER_LIST = 1
    SANDESH_FLOW_OPER_TABLE_GET = 2

    SANDESH_NH_TYPE_DEAD = 0
    SANDESH_NH_TYPE_RCV = 1
    SANDESH_NH_TYPE_ENCAP = 2
    SANDESH_NH_TYPE_TUNNEL = 3
    SANDESH_NH_TYPE_RESOLVE = 4
    SANDESH_NH_TYPE_DISCARD = 5
    SANDESH_NH_TYPE_COMPOSITE = 6
    SANDESH_NH_TYPE_VRF_TRANSLATE = 7
    SANDESH_NH_TYPE_L2_RCV = 8

    SANDESH_AF_UNIX = 1
    SANDESH_AF_INET = 2
    SANDESH_AF_BRIDGE = 7
    SANDESH_AF_INET6 = 10

    SANDESH_VIF_TYPE_HOST = 0
    SANDESH_VIF_TYPE_AGENT = 1
    SANDESH_VIF_TYPE_PHYSICAL = 2
    SANDESH_VIF_TYPE_VIRTUAL = 3
    SANDESH_VIF_TYPE_XEN_LL_HOST = 4
    SANDESH_VIF_TYPE_GATEWAY = 5
    SANDESH_VIF_TYPE_VIRTUAL_VLAN = 6
    SANDESH_VIF_TYPE_STATS = 7
    SANDESH_VIF_TYPE_VLAN = 8
    SANDESH_VIF_TYPE_MONITORING = 9

    SANDESH_VIF_TRANSPORT_VIRTUAL = 0
    SANDESH_VIF_TRANSPORT_ETH = 1
    SANDESH_VIF_TRANSPORT_PMD = 2
    SANDESH_VIF_TRANSPORT_SOCKET = 3


############################################
# Vrouter class
############################################
class vrouter:
    """Class which abstracts DPDK Vrouter actions"""

    dpdk_binary_path = ""
    socket_dir = ""

    def __init__(self, path, sock_dir):
        self.dpdk_binary_path = path
        self.socket_dir = sock_dir
        self.pid = 0
        print "Creating vrouter obj path %s \
               sock_dir %s" % (path, sock_dir)

    def run(self):
        cpid = os.fork()
        if cpid == 0:
            os.execlp("taskset", "taskset", "0x1", self.dpdk_binary_path,
                      "--no-daemon", "--no-huge", "--vr_packet_sz",
                      "2048", "--vr_socket_dir", self.socket_dir)
        else:
            print "pid of dpdk process = ", cpid
            self.pid = cpid
            count = 0
            ret2 = 0
            while (count < 10):
                cmd2 = "lsof " + self.socket_dir + "/dpdk_netlink | wc -l"
                print "Running cmd ", cmd2
                try:
                    ret2 = subprocess.check_output(cmd2, shell=True)
                    # check if the netlink is up using the ret value
                    if (ret2 == "2\n"):
                        break
                    else:
                        time.sleep(1)
                        count += 1
                except Exception as e:
                    print e
                    time.sleep(1)
                    count += 1
            if (ret2 != "2\n"):
                print "Failed to bringup vrouter"
                return -1
            else:
                return 0

    def stop(self):
        if (self.pid > 0):
            print "Stopping vrouter pid=" + str(self.pid)
            try:
                os.kill(self.pid, signal.SIGKILL)
            except OSError as e:
                print e


############################################
# Vtest class
############################################
class vtest:
    """Class to abstract vtest operations"""

    VT_SANDESH_CMD = 0
    VT_PKT_CMD = 1

    VT_RESPONSE_NOTREQD = 0
    VT_RESPONSE_REQD = 1

    vtest_binary_path = ""
    socket_dir = ""
    xml_file_path_prefix = "./tests/"

    def get_test_file_path(self):
        return self.xml_file_path_prefix + self.test_name + "_data/"

    def __init__(self, t_name):
        self.test_name = t_name
        self.vtest_binary_path = os.environ['VTEST_PATH']
        self.socket_dir = os.environ['VROUTER_SOCKET_PATH']
        self.sreq_num = 0
        shutil.rmtree(self.get_test_file_path(), ignore_errors=True)
        try:
            os.mkdir(self.get_test_file_path())
        except OSError as e:
            print e

    # api to get next sandesh req number
    def get_sandesh_req_num(self):
        self.sreq_num += 1
        return self.sreq_num

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
                print "Failed to write sandesh req file"
                print e
        try:
            subprocess.call("xmllint --format " + filename +
                            " --output " + filename, shell=True)
        except Exception as e:
            print "Failed to format xml output"
            print e

    @staticmethod
    def create_pcap_req(input_pkt_list, input_if_idx,
                        output_pkt_list, output_if_idx, req_file):
        # create the pcap files first
        inp_pcap_filename = req_file+".input.pcap"
        wrpcap(inp_pcap_filename, input_pkt_list)
        inp_pcap_filestr_list = inp_pcap_filename.split("/")
        inp_pcap_filestr = inp_pcap_filestr_list[len(inp_pcap_filestr_list)-1]
        if (output_pkt_list is not None):
            out_pcap_filename = req_file+".output.pcap"
            wrpcap(out_pcap_filename, output_pkt_list)
            out_pcap_filestr_list = out_pcap_filename.split("/")
            out_pcap_filestr = \
                out_pcap_filestr_list[len(out_pcap_filestr_list)-1]

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
                    fh.write("<pcap_excepted_file>" + out_pcap_filestr
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

    def run_command(self, is_pkt_cmd, arg1, arg2=""):
        cmd = self.vtest_binary_path + " --vr_socket_dir " + \
              self.socket_dir
        if (is_pkt_cmd == 0):
            cmd += " --send_sandesh_req " + arg1
            if (arg2):
                cmd += " --recv_sandesh_resp " + arg2
        else:
            cmd += " --send_recv_pkt " + arg1
        print "Running cmd ", cmd
        try:
            ret = subprocess.call(cmd, shell=True)
            if (ret != 0):
                print "vtest run command %s failed with err %d" % (cmd, ret)
            return ret
        except Exception as err:
            print err
            print "Failed to run vtest cmd: " + cmd
            return -1

    def parse_xml_field(self, file, field_name):
        tree = ET.parse(file)
        elem = tree.getroot().find(field_name)
        if (elem.find("list") is not None):
            return elem.find("list").text
        else:
            return elem.text

    def send_sandesh_req(self, obj_list, get_resp=VT_RESPONSE_NOTREQD):
        obj_list_internal = []
        if (isinstance(obj_list, list)):
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
            self.run_command(self.VT_SANDESH_CMD, req_filename, resp_filename)
            resp.append(resp_filename)
        if (isinstance(obj_list, list)):
            return resp
        else:
            return resp[0]

    def send_recv_pkt(self, tx_pkt_list, tx_if_idx, rx_pkt_list, rx_if_idx):
        # create the req xml file first
        filename = self.get_test_file_path() + \
                   self.test_name + "_" + str(self.get_sandesh_req_num())
        req_filename = filename + "_req.xml"
        self.create_pcap_req(tx_pkt_list, tx_if_idx, rx_pkt_list, rx_if_idx,
                             req_filename)
        # run the vtest cmd
        return self.run_command(self.VT_PKT_CMD, req_filename)

    def send_pkt(self, tx_pkt_list, tx_if_idx):
        # create the req xml file first
        filename = self.get_test_file_path() + self.test_name \
                   + "_" + str(self.get_sandesh_req_num())
        req_filename = filename + "_req.xml"
        self.create_pcap_req(tx_pkt_list, tx_if_idx, None, None, req_filename)
        # run the vtest cmd
        return self.run_command(self.VT_PKT_CMD, req_filename)



############################################
# Pytest fixtures
############################################
@pytest.fixture(scope="function")
def vrouter_test_fixture():
    # test setup code goes here
    # launch vrouter
    vr_path = os.environ['VROUTER_DPDK_PATH']
    sock_dir = os.environ['VROUTER_SOCKET_PATH']
    vr = vrouter(vr_path, sock_dir)
    print "Launching vrouter"
    vr.run()
    yield vrouter_test_fixture

    # teardown code goes after yield
    # stop vrouter
    print "Stopping vrouter"
    vr.stop()
