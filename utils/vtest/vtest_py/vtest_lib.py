#!/usr/bin/python

import subprocess
import time
import sys
import os
import shutil

sys.path.append("../../../../build/debug/tools/sandesh/library/python/")

from vr_py_sandesh.vr_py.ttypes import *
from pysandesh.transport.TTransport import *
from pysandesh.protocol.TProtocol import *
from pysandesh.protocol.TXMLProtocol import *

import xml.etree.ElementTree as ET
from scapy.all import *

class vrouter:
    "Class which abstracts DPDK Vrouter actions"

    dpdk_binary_path = ""
    socket_dir = ""
    socket_port = 0

    def __init__(self, path, sock_dir, sock_port):
       self.dpdk_binary_path = path
       self.socket_dir = sock_dir
       self.socket_port = sock_port
       print "Creating vrouter obj path %s \
              sock_dir %s sock_port %s" %(path, sock_dir, sock_port)

    def run(self):
        cmd = "taskset 0x1 "+self.dpdk_binary_path+\
              " --no-daemon --no-huge --vr_packet_sz 2048 --vr_socket_dir "+\
              self.socket_dir+" --vr_netlink_port " + self.socket_port+" &"
        print "Running cmd ", cmd
        self.pobj = subprocess.Popen(cmd, shell=True)
        count = 0
        ret2 = 0
        while (count < 10):
            cmd2 = "lsof "+ self.socket_dir +"/dpdk_netlink | wc -l"
            print "Running cmd ", cmd2
            ret2 = subprocess.check_output(cmd2, shell=True)
            if (ret2 == "2\n"):
                break
            else:
                time.sleep(1)
                count += 1
        if (ret2 != "2\n"):
            print "Failed to bringup vrouter"
            return -1
        else:
            return 0

    def stop(self):
        print "Stopping vrouter "
        plist = subprocess.check_output("ps -aux | grep vr_netlink_port", shell=True)
        pid = plist.split(" ")[5]
        killcmd = "kill -9 "+str(pid)
        subprocess.call(killcmd, shell=True)

class vtest:
    "Class to abstract vtest operations"

    sreq_num = 0
    test_name = ""
    vtest_binary_path = ""
    socket_dir = ""
    socket_port = ""
    xml_file_path_prefix = "./tests/"

    def __init__(self, t_name, vtest_path, sock_dir, sock_port):
        self.test_name = t_name
        self.vtest_binary_path = vtest_path
        self.socket_dir = sock_dir
        self.socket_port = sock_port

    # api to get next sandesh req number
    def get_sandesh_req_num(self):
        self.sreq_num += 1
        return self.sreq_num

    # create xml proto with file handle
    def get_xml_proto_file_handle(self, filehandle):
        ft = TFileObjectTransport(filehandle)
        xml_proto = TXMLProtocol(ft)
        return xml_proto

    # creates a sandesh req in xml file format
    def create_sandesh_req(self, obj, filename):
        msghdr = "<?xml version=\"1.0\"?><test><test_name>sandesh req</test_name><message>"
        msgfooter = "</message></test>"
        # open the file
        fh = open(filename, "w")
        # write msg hdr
        fh.write(msghdr)
        # write sandesh xml output of the obj
        obj.write(self.get_xml_proto_file_handle(fh))
        fh.write(msgfooter)
        fh.close()
    
    def create_pcap_req(self, input_pkt, input_if_idx, output_pkt, output_if_idx, req_file):
        # create the pcap files first
        inp_pcap_filename = req_file+".input.pcap"
        wrpcap(inp_pcap_filename, input_pkt)
        inp_pcap_filestr_list = inp_pcap_filename.split("/")
        inp_pcap_filestr = inp_pcap_filestr_list[len(inp_pcap_filestr_list)-1]
        if (output_pkt is not None):
            out_pcap_filename = req_file+".output.pcap"
            wrpcap(out_pcap_filenam, output_pkt)
            out_pcap_filestr_list = out_pcap_filename.split("/")
            out_pcap_filestr = out_pcap_filestr_list[len(out_pcap_filestr_list)-1]

        # write the request file now
        hdr = "<?xml version=\"1.0\"?><test><test_name>pkt test</test_name><packet>"
        footer = "</packet></test>"

        fh = open(req_file, "w")
        fh.write(hdr)
        fh.write("<pcap_input_file>"+inp_pcap_filestr+"</pcap_input_file>\n")
        if (output_pkt is not None):
            fh.write("<pcap_excepted_file>"+out_pcap_filestr
                     +"</pcap_expected_file>\n")
        fh.write("<tx_interface> <vif_index>"+input_if_idx
                 +"</vif_index></tx_interface>\n")
        if (output_pkt is not None):
            fh.write("<rx_interface> <vif_index>"+output_if_idx+
                     "</vif_index> </rx_interface>\n")
        fh.write(footer)
        fh.close()

    def run_command(self, is_pkt_cmd, arg1, arg2=""):
        cmd = self.vtest_binary_path + " --vr_socket_dir " + self.socket_dir + " --vr_netlink_port " + self.socket_port
        if (is_pkt_cmd == 0):
            cmd += " --send_sandesh_req "+ arg1
            if (arg2):
                cmd += " --recv_sandesh_resp "+arg2
        else:
            cmd += " --send_recv_pkt "+ arg1
        print "Running cmd ", cmd
        ret = subprocess.call(cmd, shell=True)
        if (ret != 0):
            print "vtest run command %s failed with err %d" %(cmd, ret)
        return ret
    
    def parse_xml_field(self, file, field_name):
        tree = ET.parse(file)
        elem = tree.getroot().find(field_name)
        if (elem.find("list") is not None):
            return elem.find("list").text
        else:
            return elem.text

    def send_sandesh_req(self, obj, get_resp=0):
        # create the req xml file
        filename = self.xml_file_path_prefix + self.test_name \
                   + "_" + str(self.get_sandesh_req_num())
        req_filename = filename + "_req.xml"
        resp_filename = ""
        self.create_sandesh_req(obj, req_filename)
        # run the vtest cmd
        if (get_resp == 1):
            resp_filename = filename + "_resp.xml"
        self.run_command(0, req_filename, resp_filename)
        return resp_filename

    def send_recv_pkt(self, tx_pkt, tx_if_idx, rx_pkt, rx_if_idx):
        # create the req xml file first
        filename = self.xml_file_path_prefix + \
                   self.test_name + "_" + str(self.get_sandesh_req_num())
        req_filename = filename + "_req.xml"
        self.create_pcap_req(tx_pkt, tx_if_idx, rx_pkt, rx_if_idx, req_filename)
        # run the vtest cmd
        return self.run_command(1, req_filename)

    def send_pkt(self, tx_pkt, tx_if_idx):
        # create the req xml file first
        filename = self.xml_file_path_prefix + self.test_name \
                   + "_" + str(self.get_sandesh_req_num())
        req_filename = filename + "_req.xml"
        self.create_pcap_req(tx_pkt, tx_if_idx, None, None, req_filename)
        # run the vtest cmd
        return self.run_command(1, req_filename)

