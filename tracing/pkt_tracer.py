from bcc import BPF
from time import sleep, strftime
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import struct
import socket
import ipaddress as ip
import netaddr
import re
import ctypes as ct
import os
import sys
import signal

start = 0
fd = open("trace_output", "w")
indent = 0

def stp_handler(signum, frame):
    global indent
    global fd
    fd.close()
    arr = []
    fr = open("trace_output", "r")
    next(fr)
    for line in fr:
        arr.append(line)
    arr.sort(key=lambda x: float(x.split(" ")[0]))
    fr.close()
    fd = open("trace_output", "w")
    for line in arr:
        fd.write(line)
        if '{' in line:
            indent += 1
        elif '}' in line:
            indent -= 1
            if indent == 0:
               fd.write("\n")
    fd.close()
    print("Check trace_output file for output")
    exit()

class Data(ct.Structure):
    _fields_ = [("pid", ct.c_int),
                ("ts", ct.c_ulonglong),
                ("comm", ct.c_char * 16), ("saddr", ct.c_uint),
                ("daddr", ct.c_uint), ("protocol", ct.c_uint), ("sport", ct.c_uint),
                ("dport", ct.c_uint), ("ret", ct.c_int), ("trace_val", ct.c_int), ("return_val", ct.c_int)]

class Probe(object):
    def __init__(self, probe_name, handler, ret_handler, event, ret_flag, org_flag):
        self.probe_name = probe_name
        self.handler = handler
        self.ret_handler = ret_handler
        self.events_name = event
        self.return_flag = ret_flag
	self.org = org_flag

    def _generate_program(self, args, largs):
        self.text = """
            BPF_PERF_OUTPUT(%s);
            int %s(struct pt_regs *ctx) {
                int zero = 0, one = 1, mone = -1;
                struct data_t data = {};
                struct vr_packet p = {};
                bpf_get_current_comm(&data.comm, sizeof(data.comm));
                bpf_probe_read(&p, sizeof(p), (void *)PT_REGS_PARM2(ctx));
                data.pid = bpf_get_current_pid_tgid();

                int *val = trace_map.lookup_or_init(&data.pid, &zero);
                data.trace_val = *val;
                data.ts = bpf_ktime_get_ns();
                data.ret = 0;
                struct iphdr *ih = (struct iphdr *)(p.vp_head + p.vp_network_h);
                struct iphdr iph = {};
                bpf_probe_read(&iph, sizeof(iph), ih);
                data.saddr = iph.saddr;
                data.daddr = iph.daddr;

                data.protocol = iph.protocol;
                if(data.protocol == 6) {
                    struct vr_tcp tcp = {};
                    bpf_probe_read(&tcp, sizeof(tcp), (struct vr_tcp *) (p.vp_head + p.vp_data));
                    data.sport = tcp.tcp_sport;
                    data.dport = tcp.tcp_dport;
                }
                else if(data.protocol == 17) {
                    struct vr_udp udp = {};
                    bpf_probe_read(&udp, sizeof(udp), (struct vr_udp *) (p.vp_head + p.vp_data));
                    data.sport = udp.udp_sport;
                    data.dport = udp.udp_dport;
                }""" %(self.events_name, self.handler)
        self.text += """if(data.saddr == 0 || data.daddr == 0) data.trace_val = 0;
                else {
                    if("""+str(args["src"] != 0).lower()+""" && data.saddr != 0) {
                        if(data.saddr == """+str(args["src"])+""") {
                            trace_map.update(&data.pid, &one);
                            data.trace_val = 1;
                        }
                        else {
                            trace_map.update(&data.pid, &mone);
                            data.trace_val = -1;
                            return 0;
                        }
                    }

                    if("""+str(args["dest"] != 0).lower()+""" && data.daddr != 0) {
                        if(data.daddr == """+str(args["dest"])+""") {
                            trace_map.update(&data.pid, &one);
                            data.trace_val = 1;
                        }
                        else {
                            trace_map.update(&data.pid, &mone);
                            data.trace_val = -1;
                            return 0;
                        }
                    }

                    if("""+str(args["protocol"] != 0).lower()+""" && data.protocol != 0) {
                        if(data.protocol == """+str(args["protocol"])+""") {
                            trace_map.update(&data.pid, &one);
                            data.trace_val = 1;
                        }
                        else {
                            trace_map.update(&data.pid, &mone);
                            data.trace_val = -1;
                            return 0;
                        }
                    }

                    if("""+str(args["sport"] != 0).lower()+""" && data.sport != 0) {
                        if(data.sport == """+str(args["sport"])+""") {
                            trace_map.update(&data.pid, &one);
                            data.trace_val = 1;
                        }
                        else {
                            trace_map.update(&data.pid, &mone);
                            data.trace_val = -1;
                            return 0;
                        }
                    }

                    if("""+str(args["dport"] != 0).lower()+""" && data.dport != 0) {
                        if(data.dport == """+str(args["dport"])+""") {
                            trace_map.update(&data.pid, &one);
                            data.trace_val = 1;
                        }
                        else {
                            trace_map.update(&data.pid, &mone);
                            data.trace_val = -1;
                            return 0;
                        }
                    }
                }
                """
        if largs == 0:
            self.text += """
                    %s.perf_submit(ctx, &data, sizeof(data));
                    return 0;
                }""" %(self.events_name)
        else:
            self.text += """
		    int *tval = trace_map.lookup_or_init(&data.pid, &zero);
                    if(*tval == 1) {
                        %s.perf_submit(ctx, &data, sizeof(data));
                    }
                    return 0;
                }""" %(self.events_name)
        self.text += """
            int %s(struct pt_regs *ctx) {
                int zero = 0, one = 1, mone = -1;
                struct data_t data = {};
                data.ts = bpf_ktime_get_ns();
                data.pid = bpf_get_current_pid_tgid();
                bpf_get_current_comm(&data.comm, sizeof(data.comm));
                data.return_val = PT_REGS_RC(ctx);
                data.ret = 1;
                """ %(self.ret_handler)
        if largs == 0:
            self.text += """
                %s.perf_submit(ctx, &data, sizeof(data));
                return 0;
            }""" %(self.events_name)
        else:
            self.text += """
                int *val = trace_map.lookup_or_init(&data.pid, &zero);
                if(*val == 1)
                %s.perf_submit(ctx, &data, sizeof(data));
                return 0;
            }
        """ %(self.events_name)
        return self.text

    def print_event(self, cpu, data, size):
        self.event = ct.cast(data, ct.POINTER(Data)).contents
        global start
        global fd
        if start == 0:
            start = self.event.ts
        time_s = (float(self.event.ts-start))/1000000000
        function = "%-13.9f %-12s %-10d %-15s %-15s %-10d %-10d %-10d" %(time_s, self.event.comm, self.event.pid,
                    inet_ntop(AF_INET, pack("I", self.event.saddr)), inet_ntop(AF_INET, pack("I", self.event.daddr)),
                    self.event.protocol, self.event.sport, self.event.dport)
        if self.event.ret == 0:
           print(function + "   " + self.probe_name + " {")
           fd.write(function + "   " + self.probe_name + " {\n")
        else:
           if self.return_flag == False:
              fd.write(function + "   " + " }\n")
	   else:
	      fd.write(function + "   " + "}             "+self.probe_name + "   " + str(self.event.return_val) + "\n")

    def attach_probe(self, bpf):
        bpf.attach_kprobe(event=self.probe_name, fn_name=self.handler)
        bpf.attach_kretprobe(event=self.probe_name, fn_name=self.ret_handler)
        bpf[self.events_name].open_perf_buffer(self.print_event)

class Tool(object):
    def __init__(self):
        self.cmd_args = sys.argv[1:]
        self.file = ""
        self.return_flag = False
        self.help_flag = False
        self.org = False
        self.largs = 0
        self.args = {"src":0, "dest":0, "protocol":0, "sport":0, "dport":0}
        i = 0
        while (i < len(self.cmd_args)):
            if self.cmd_args[i] == '-h' or self.cmd_args[i] == '-help':
                self.print_help()
                self.help_flag = True
                break
            if self.cmd_args[i] == '-f':
                self.file = self.cmd_args[i+1]
                i = i+1
            elif self.cmd_args[i] == '-r':
                self.return_flag = True
            elif self.cmd_args[i] == '-o':
		self.org = True
            elif self.cmd_args[i] == '-a':
                for arg in self.cmd_args[i+1:]:
                    self.largs += 1
                    name, val = arg.split('=')
                    if name == 'src' or name == 'dest':
                       val = int(netaddr.IPAddress('.'.join(val.split('.')[::-1])))
                    self.args[name] = int(val)
                break
            i = i+1

    def print_help(self):
        help_string = """
Flags available:          Function:          Description:
-f                        File Name          Give name of the file you want to trace symbols from after -f flag.
-r                        Return Value       Print the return value of every function that is being probed (Note only integer return value will be printed, so user must interpret accordingly)
-h                        Help               Prints the documentation
-a                        Arguments          Give the arguments to program on the basis of which packets are to be filtered followed by -a flag
-o			  Organize output    Organize output to form a packet flow.

Arguments available:      Name:
src                       Source IP address
dest                      Destination IP address
protocol                  Protocol
sport                     Source Port
dport                     Destination Port


Examples:

python pkt_tracer.py -f func                                                                                --Traces all symbols within func file
python pkt_tracer.py -f func -r                                                                             --Traces all symbols within func file and also prints the return values from those symbols
python pkt_tracer.py -f func -a src=192.168.100.3                                                           --Traces only those packets whose source IP address is 192.168.100.3
python pkt_tracer.py -f func -a src=192.168.100.3 dest=192.168.100.4                                        --Traces only those packets whose source IP is 192.168.100.3 and destination IP is 192.168.100.4
python pkt_tracer.py -f func -o -a src=192.168.100.3 dest=192.168.100.4 protocol=6 sport=4165 dport=16387      --Traces only those packets that satisfy all the filters applied

"""
        print(help_string)

    def _create_probes(self):
        self.probes = []
        f = open(self.file, 'r')
        for line in f:
            line = line.strip()
            self.probes.append(Probe(line, "probe_handler_"+line, "ret_probe_handler_"+line, "events_"+line, self.return_flag, self.org))

    def _generate_program(self):
        self.prog = """
            #include <linux/ptrace.h>
            #include <linux/sched.h>
            #include <linux/ip.h>

            struct vr_tcp {
                unsigned short tcp_sport;
                unsigned short tcp_dport;
                unsigned int tcp_seq;
                unsigned int tcp_ack;
                uint16_t tcp_offset_r_flags;
                unsigned short tcp_win;
                unsigned short tcp_csum;
                unsigned short tcp_urg;
            };
            struct vr_udp {
                unsigned short udp_sport;
                unsigned short udp_dport;
                unsigned short udp_length;
                unsigned short udp_csum;
            };
            struct vr_packet {
                unsigned char *vp_head;
                struct vr_interface *vp_if;
                struct vr_nexthop *vp_nh;
                unsigned short vp_data;
                unsigned short vp_tail;
                unsigned short vp_len;
                unsigned short vp_end;
                unsigned short vp_network_h;
                unsigned short vp_flags;
                unsigned short vp_inner_network_h;
                unsigned char vp_cpu;
                unsigned char vp_type;
                unsigned char vp_ttl;
                unsigned char vp_queue;
                unsigned char vp_priority:4,
                              vp_notused:4;
            };

            struct data_t {
                u32 pid;
                u64 ts;
                char comm[TASK_COMM_LEN];
                __u32 saddr;
                __u32 daddr;
                __u8 protocol;
                __u32 sport;
                __u32 dport;
                int ret;
                int trace_val;
                int return_val;
            };
            BPF_HASH(trace_map, u32, int, 1024);
        """
        for probe in self.probes:
            self.prog += probe._generate_program(self.args, self.largs)

    def _attach_probes(self):
        self.bpf = BPF(text=self.prog)
        for probe in self.probes:
            probe.attach_probe(self.bpf)

    def _main_loop(self):
        global fd
        if self.org == True:
	   signal.signal(signal.SIGINT, stp_handler)
        while True:
            self.bpf.perf_buffer_poll()

    def run(self):
        self._create_probes()
        self._generate_program()
        self._attach_probes()
        print("Attached probes")
        print("Tracing......   Press ctrl-c to stop")
        self._main_loop()


if __name__ == "__main__":
    t = Tool()
    fd = open("trace_output", "w")
    if t.help_flag == False:
       fd.write("%-15s %-11s %-10s %-15s %-10s %-12s %-10s %-18s %s\n" % ("TIME(S)", "COMM", "PID", "saddr", "daddr", "protocol", "sport", "dport", "Trace"))
       t.run()
