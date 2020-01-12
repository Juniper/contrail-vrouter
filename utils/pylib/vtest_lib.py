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
import pytest
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
    ip6_u = int(bin(netaddr.IPAddress(str) >> 64),2)
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
    baseclass_name = mro_tuple[mro_len-2].__name__
    print "Replacing "+ subclass_name + " with " + baseclass_name
    try:
        subprocess.call("sed -i 's/" + subclass_name + "/" + baseclass_name + "/g' " + file,
                        shell=True)
    except Exception as e:
        print "Failed to replace sandesh obj name = ", subclass_name
        print e


############################################
# Vrouter class
############################################
class vrouter:
    """Class which abstracts DPDK Vrouter actions"""

    dpdk_binary_path = ""
    socket_dir = ""

    def __init__(self, path, sock_dir, vtest_only):
        self.dpdk_binary_path = path
        self.socket_dir = sock_dir
        self.vtest_only = vtest_only
        self.pid = 0

    def run(self):
        if (self.vtest_only):
            return 0
        cpid = os.fork()
        if cpid == 0:
            os.execlp("taskset", "taskset", "0x1", self.dpdk_binary_path,
                      "--no-daemon", "--no-huge", "--vr_packet_sz",
                      "2048", "--vr_socket_dir", self.socket_dir)
        else:
            print "Running cmd - taskset 0x1 %s --no-daemon --no-huge --vr_packet_sz 2048 "\
                  "--vr_socket_dir %s" % (self.dpdk_binary_path, self.socket_dir)
            print "pid = " + str(cpid)
            self.pid = cpid
            count = 0
            ret2 = 0
            while (count < 10):
                cmd2 = "lsof " + self.socket_dir + "/dpdk_netlink | wc -l"
                print "Running cmd - ", cmd2
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
        if (self.vtest_only):
            return
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
        import pdb; pdb.set_trace()
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
            replace_sandesh_obj_name(obj, filename)
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
# Vif class
############################################
class VIF(vr_interface_req):
    """Class to represent vif object"""

    def __init__(self, idx, name, ip, mac, type=vtconst.VIF_TYPE_VIRTUAL, ip6_u=0, ip6_l=0):
        super(VIF, self).__init__()
        self.h_op = vtconst.SANDESH_OPER_ADD
        self.vifr_type = type
        self.vifr_idx = idx
        self.vifr_name = name
        self.vifr_transport = vtconst.VIF_TRANSPORT_PMD
        self.vifr_vrf = 0
        self.vifr_mac = mac
        self.vifr_mtu = 1514
        self.vifr_ip = ip
        self.vifr_ip6_u = ip6_u
        self.vifr_ip6_l = ip6_l


############################################
# Nexthop class
############################################
class NH(vr_nexthop_req):
    """Class to represent nexthop object"""

    def __init__(self, id, type, family, encap_oif, encap):
        super(NH, self).__init__()
        self.h_op = vtconst.SANDESH_OPER_ADD
        self.nhr_id = id
        self.nhr_family = family
        self.nhr_type = type
        self.nhr_vrf = 0
        self.nhr_flags = vtconst.NH_FLAG_VALID
        self.nhr_encap_oif_id = encap_oif
        self.nhr_encap = encap


############################################
# Encap Nexthop class
############################################
class ENCAP_NH(NH):
    """Class to represent encap nexthop object, derived from nh"""

    def __init__(self, id, family, encap_oif, encap):
        super(ENCAP_NH, self).__init__(id, vtconst.NH_TYPE_ENCAP, family, encap_oif, encap)


############################################
# Tunnel Nexthop class (IPv4)
############################################
class TUNNEL_NHV4(NH):
    """Class to represent ipv4 tunnel nexthop object, derived from nh"""

    def __init__(self, id, tun_sip, tun_dip, encap_oif, encap):
        super(TUNNEL_NHV4, self).__init__(id, vtconst.NH_TYPE_TUNNEL, vtconst.AF_INET, encap_oif, encap)
        self.nhr_tun_sip = tun_sip
        self.nhr_tun_dip = tun_dip


############################################
# Tunnel Nexthop class (IPv6)
############################################
class TUNNEL_NHV6(NH):
    """Class to represent ipv6 tunnel nexthop object, derived from nh"""

    def __init__(self, id, tun_sip6, tun_dip6, encap_oif, encap):
        super(TUNNEL_NHV6, self).__init__(id, vtconst.NH_TYPE_TUNNEL, vtconst.AF_INET6, encap_oif, encap)
        self.nhr_tun_sip6 = tun_sip6
        self.nhr_tun_dip6 = tun_dip6



############################################
# Route class
############################################
class RT(vr_route_req):
    """Class to represent route object"""

    def __init__(self, family, vrf, prefix=None, prefix_len=None, mac=None, nh_id=None):
        super(RT, self).__init__()
        self.h_op = vtconst.SANDESH_OPER_ADD
        self.rtr_family = family
        self.rtr_vrf_id = vrf
        self.rtr_mac = mac
        self.rtr_prefix = prefix
        self.rtr_prefix_len = prefix_len
        self.rtr_nh_id = nh_id


############################################
# Bridge Route class
############################################
class BRIDGE_RT(RT):
    """Class to represent bridge route object"""

    def __init__(self, vrf, mac, nh_id):
        super(BRIDGE_RT, self).__init__(vtconst.AF_BRIDGE, vrf, None, None, mac, nh_id)


############################################
# Inet Route class
############################################
class INET_RT(RT):
    """Class to represent inet route object"""

    def __init__(self, vrf, prefix, prefix_len, nh_id):
        super(INET_RT, self).__init__(vtconst.AF_INET, vrf, prefix, prefix_len, None, nh_id)


############################################
# Inet6 Route class
############################################
class INET6_RT(RT):
    """Class to represent inet6 route object"""

    def __init__(self, vrf, prefix, prefix_len, nh_id):
        super(INET6_RT, self).__init__(vtconst.AF_INET6, vrf, prefix, prefix_len, None, nh_id)


############################################
# Flow class
############################################
class FLOW(vr_flow_req):
    """Class to represent flow object"""

    def __init__(self, idx, sip_l, sip_h, dip_l, dip_h, family, proto, sport, dport):
        super(FLOW, self).__init__()
        self.fr_op = vtconst.FLOW_OPER_SET
        self.fr_index = idx
        self.fr_rindex = -1
        self.fr_flow_sip_l = sip_l
        self.fr_flow_sip_h = sip_h
        self.fr_flow_dip_l = dip_l
        self.fr_flow_dip_h = dip_h
        self.fr_family = family
        self.fr_flow_proto = proto
        self.fr_flow_sport = socket.htons(sport)
        self.fr_flow_dport = socket.htons(dport)
        self.fr_flags = vtconst.VR_FLOW_FLAG_ACTIVE
        self.fr_ecmp_nh_index = -1
        self.fr_action = vtconst.VR_FLOW_ACTION_FORWARD
        self.fr_qos_id = -1
        # set reverse flow params as mirror of forward flow by default
        self.rflow_sip_u = self.fr_flow_dip_u
        self.rflow_sip_l = self.fr_flow_dip_l
        self.rflow_dip_u = self.fr_flow_sip_u
        self.rflow_dip_l = self.fr_flow_sip_l
        self.rflow_sport = self.fr_flow_dport
        self.rflow_dport = self.fr_flow_sport


############################################
# Inet Flow class
############################################
class INET_FLOW(FLOW):
    """Class to represent inet flow object"""

    def __init__(self, idx, sip, dip, proto, sport, dport):
        super(INET_FLOW, self).__init__(idx, sip, 0, dip, 0, vtconst.AF_INET, proto, sport, dport)


############################################
# Inet6 Flow class
############################################
class INET6_FLOW(FLOW):
    """Class to represent inet6 flow object"""

    def __init__(self, idx, sip6, dip6, proto, sport, dport):
        super(INET6_FLOW).__init__(idx, sip6[0], sip6[1], dip6[0], dip6[1], \
                         vtconst.AF_INET6, proto, sport, dport)


############################################
# Dropstats class
############################################
class DROPSTATS(vr_drop_stats_req):
    """Class to represent dropstats object"""

    def __init__(self):
        super(DROPSTATS, self).__init__()
        self.h_op = vtconst.SANDESH_OPER_GET


############################################
# Pytest fixtures
############################################
@pytest.fixture(scope="function")
def vrouter_test_fixture():
    # test setup code goes here
    # launch vrouter
    vr_path = os.environ['VROUTER_DPDK_PATH']
    sock_dir = os.environ['VROUTER_SOCKET_PATH']
    vtest_only = os.environ['VTEST_ONLY_MODE']
    vr = vrouter(vr_path, sock_dir, int(vtest_only))
    print "Launching vrouter"
    vr.run()
    yield vrouter_test_fixture

    # teardown code goes after yield
    # stop vrouter
    print "Stopping vrouter"
    vr.stop()

