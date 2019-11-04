#!/usr/bin/python

import subprocess
import time
import os
import shutil
import signal
import socket
import ipaddress
import netaddr

from vr_py_sandesh.vr_py.ttypes import *
from pysandesh.transport.TTransport import *
from pysandesh.protocol.TProtocol import *
from pysandesh.protocol.TXMLProtocol import *

import xml.etree.ElementTree as ET
from scapy.all import *
import vtconst
import inspect
############################################
# Utility functions
############################################


def htonll(val):
    return (socket.htonl(val & 0xFFFFFFFF) << 32) + (socket.htonl(val >> 32))


def ntohll(val):
    return (socket.ntohl(val & 0xFFFFFFFF) << 32) + (socket.ntohl(val >> 32))


def vt_encap(str):
    blist = list(str.replace(' ', '').decode('hex'))
    for i in range(len(blist)):
        blist[i] = ord(blist[i])
    return blist


def vt_mac(str):
    blist = list(str.replace(':', '').decode('hex'))
    for i in range(len(blist)):
        blist[i] = ord(blist[i])
    return blist


def vt_ipv4(str):
    return socket.htonl(int(ipaddress.IPv4Address(unicode(str))))


def vt_ipv4_bytes(str):
    ipv4_sp = str.split(".")
    ipv4_dec = []
    for i in range(len(ipv4_sp)):
        ipv4_dec.append(int(ipv4_sp[i]))
    return ipv4_dec


def vt_ipv6(str):
    ip6_u = int(bin(netaddr.IPAddress(str) >> 64), 2)
    ip6_l = int(bin(netaddr.IPAddress(str) & (1 << 64) - 1), 2)
    return htonll(ip6_u), htonll(ip6_l)

# replace sandesh obj name in xml file generated
# as pysandesh uses the derived class name to write the req;
# eg: vif instead of vr_interface_req as vif is derived from vr_interface_req


def replace_sandesh_obj_name(obj, file):
    subclass_name = obj.__class__.__name__
    mro_tuple = inspect.getmro(obj.__class__)
    mro_len = len(mro_tuple)
    if (mro_len <= 2):
        # there is no base class
        print "Subclass is same as base class, ", subclass_name
        return
    baseclass_name = mro_tuple[mro_len - 2].__name__
    print "Replacing " + subclass_name + " with " + baseclass_name
    try:
        subprocess.call(
            "sed -i 's/" +
            subclass_name +
            "/" +
            baseclass_name +
            "/g' " +
            file,
            shell=True)
    except Exception as e:
        print "Failed to replace sandesh obj name = ", subclass_name
        print e


class Testcase(object):
    @classmethod
    def tearDownClass(self, method):
        self.vr.kill_vrouter_instance()

    @classmethod
    def setUpClass(self, method):
        self.vr = test_common_Testcase()
        test_common_Testcase.launch_vtest(method.__name__)
        vtest_only = int(os.environ['VTEST_ONLY_MODE'])
        print vtest_only
        self.vr.launch_vrouter_instance(vtest_only)
        print("Launching vrouter")
        self.vr.run()


class test_common_Testcase(Testcase, object):

    VT_SANDESH_CMD = 0
    VT_PKT_CMD = 1

    VT_RESPONSE_NOTREQD = 0
    VT_RESPONSE_REQD = 1

    sreq_num = 0
    test_name = ""
    sb_path = '../../../../../build'
    dpdk_binary_path = ""
    vtest_binary_path = ""
    socket_dir = ""
    xml_file_path_prefix = "./tests/"
    @classmethod
    def setUpClass(self, method):
        super(test_common_Testcase, self).setUpClass(method)

    @classmethod
    def tearDownClass(self, method):
        super(test_common_Testcase, self).tearDownClass(method)

    def launch_vrouter_instance(self, vtest_only=0):
        self.dpdk_binary_path = self.sb_path + '/debug/vrouter/dpdk/contrail-vrouter-dpdk'
        self.socket_dir = self.sb_path + '/debug/vrouter/utils/vtest_py_venv/var/run/vrouter'
        self.vtest_only = vtest_only
        self.pid = 0

    def kill_vrouter_instance(self):
        self.stop()

    def run(self):
        if (self.vtest_only):
            print("VTEST_ONLY_RETURN " + str(self.vtest_only))
            return 0
        print
        cpid = os.fork()
        print(os.getcwd())
        if cpid == 0:
            os.execlp("taskset", "taskset", "0x3", self.dpdk_binary_path,
                      "--no-daemon", "--no-huge", "--vr_packet_sz",
                      "2048", "--vr_socket_dir", self.socket_dir)
        else:
            print(
                "Running cmd - taskset 0x3 %s --no-daemon --no-huge --vr_packet_sz 2048 "
                "--vr_socket_dir %s" %
                (self.dpdk_binary_path, self.socket_dir))
            print("pid = " + str(cpid))
            self.pid = cpid
            count = 0
            ret2 = 0
            while (count < 10):
                print(os.getcwd())
                cmd2 = "lsof " + self.socket_dir + "/dpdk_netlink | wc -l"
                print("Running cmd - ", cmd2)
                try:
                    ret2 = subprocess.check_output(cmd2, shell=True)
                    # check if the netlink is up using the ret value
                    if (ret2 == "2\n"):
                        break
                    else:
                        time.sleep(1)
                        count += 1
                except Exception as e:
                    print(e)
                    time.sleep(1)
                    count += 1
            if (ret2 != "2\n"):
                print("Failed to bringup vrouter")
                return -1
            else:
                return 0

    def stop(self):
        if (self.vtest_only):
            return
        if (self.pid > 0):
            print("Stopping vrouter pid=" + str(self.pid))
            try:
                os.kill(self.pid, signal.SIGKILL)
            except OSError as e:
                print(e)

    # vtest methods
    @classmethod
    def get_test_file_path(self):
        return self.xml_file_path_prefix + self.test_name + "_data/"

    @classmethod
    def launch_vtest(self, t_name):
        self.test_name = t_name
        self.vtest_binary_path = '/root/contrail/build/debug/vrouter/utils/vtest/vtest'
        self.socket_dir = '/root/contrail/build/debug/vrouter/utils/vtest_py_venv/var/run/vrouter'
        self.sreq_num = 0
        shutil.rmtree(self.get_test_file_path(), ignore_errors=True)
        try:
            os.mkdir(self.get_test_file_path())
        except OSError as e:
            print(e)

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
                print("Failed to write sandesh req file")
                print(e)
        try:
            replace_sandesh_obj_name(obj, filename)
            subprocess.call("xmllint --format " + filename +
                            " --output " + filename, shell=True)
        except Exception as e:
            print("Failed to format xml output")
            print(e)

    @staticmethod
    def create_pcap_req(
            input_pkt_list,
            input_if_idx,
            output_pkt_list,
            output_if_idx,
            req_file,
            output_pcap=""):
        # create the pcap files first
        inp_pcap_filename = req_file + ".input.pcap"
        wrpcap(inp_pcap_filename, input_pkt_list)
        inp_pcap_filestr_list = inp_pcap_filename.split("/")
        inp_pcap_filestr = inp_pcap_filestr_list[len(
            inp_pcap_filestr_list) - 1]
        if (output_pkt_list is not None):
            exp_pcap_filename = req_file + ".expected.pcap"
            wrpcap(exp_pcap_filename, output_pkt_list)
            exp_pcap_filestr_list = exp_pcap_filename.split("/")
            exp_pcap_filestr = \
                exp_pcap_filestr_list[len(exp_pcap_filestr_list) - 1]

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
                    if (output_pcap != ""):
                        fh.write(
                            "<pcap_output_file>" +
                            output_pcap +
                            "</pcap_output_file>")
                    fh.write("<pcap_expected_file>" + exp_pcap_filestr
                             + "</pcap_expected_file>\n")
                fh.write("<tx_interface> <vif_index>" + input_if_idx
                         + "</vif_index></tx_interface>\n")
                if (output_pkt_list is not None):
                    fh.write("<rx_interface> <vif_index>" + output_if_idx +
                             "</vif_index> </rx_interface>\n")
                fh.write(footer)
            except Exception as e:
                print("Failed to write pcap req file")
                print(e)
        try:
            subprocess.call("xmllint --format " + req_file +
                            " --output " + req_file, shell=True)
        except Exception as e:
            print(e)
            print("Failed to format xml output")

    def run_command(self, is_pkt_cmd, arg1, arg2=""):
        cmd = self.vtest_binary_path + " --vr_socket_dir " + \
            self.socket_dir
        if (is_pkt_cmd == 0):
            cmd += " --send_sandesh_req " + arg1
            if (arg2):
                cmd += " --recv_sandesh_resp " + arg2
        else:
            cmd += " --send_recv_pkt " + arg1
        print("Running cmd ", cmd)
        try:
            ret = subprocess.call(cmd, shell=True)
            if (ret != 0):
                print("vtest run command %s failed with err %d" % (cmd, ret))
            return ret
        except Exception as err:
            print(err)
            print("Failed to run vtest cmd: " + cmd)
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

    def send_recv_pkt_compare(
            self,
            tx_pkt_list,
            tx_if_idx,
            rx_pkt_list,
            rx_if_idx):
        # create the req xml file first
        filename = self.get_test_file_path() + \
            self.test_name + "_" + str(self.get_sandesh_req_num())
        req_filename = filename + "_req.xml"
        self.create_pcap_req(tx_pkt_list, tx_if_idx, rx_pkt_list, rx_if_idx,
                             req_filename)
        # run the vtest cmd
        return self.run_command(self.VT_PKT_CMD, req_filename)

    def send_recv_pkt(self, tx_pkt_list, tx_if_idx, rx_pkt_list, rx_if_idx):
        # create the req xml file
        filename = self.get_test_file_path() + \
            self.test_name + "_" + str(self.get_sandesh_req_num())
        req_filename = filename + "_req.xml"
        output_pcap = "/tmp/output_" + str(time.time()) + ".pcap"
        self.create_pcap_req(tx_pkt_list, tx_if_idx, rx_pkt_list, rx_if_idx,
                             req_filename, output_pcap)
        # run the vtest cmd
        self.run_command(self.VT_PKT_CMD, req_filename)
        scapy_cap = rdpcap(output_pcap)
        return scapy_cap

    def send_pkt(self, tx_pkt_list, tx_if_idx):
        # create the req xml file first
        filename = self.get_test_file_path() + self.test_name \
            + "_" + str(self.get_sandesh_req_num())
        req_filename = filename + "_req.xml"
        self.create_pcap_req(tx_pkt_list, tx_if_idx, None, None, req_filename)
        # run the vtest cmd
        return self.run_command(self.VT_PKT_CMD, req_filename)
