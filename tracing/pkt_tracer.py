from bcc import BPF
import ctypes as ct
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import struct
import socket
import sys
import ipaddress as ip
import netaddr


def print_help():
    help_string = """
Flags available:          Function:          Description:
-f                        File Name          Give name of the file you want to trace symbols from after -f flag.
-r                        Return Value       Print the return value of every function that is being probed (Note only integer return value will be printed, so user must interpret accordingly)
-h                        Help               Prints the documentation
-a                        Arguments          Give the arguments to program on the basis of which packets are to be filtered followed by -a flag


Arguments available:      Name:
src                       Source IP address
dest                      Destination IP address
protocol                  Protocol
sport                     Source Port
dport                     Destination Port


Examples:

python pkt_tracer.py -f func                                                                                                              --Traces all symbols within func file
python pkt_tracer.py -f func -r                                                                                                           --Traces all symbols within func file and also prints the return values from those symbols
python pkt_tracer.py -f func -a src=192.168.100.3                                                                                         --Traces only those packets whose source IP address is 192.168.100.3
python pkt_tracer.py -f func -a src=192.168.100.3 dest=192.168.100.4                                                                      --Traces only those packets whose source IP is 192.168.100.3 and destination IP is 192.168.100.4
python pkt_tracer.py -f func -a src=192.168.100.3 dest=192.168.100.4 protocol=6 sport=4165 dport=16387                                    --Traces only those packets that satisfy all the filters applied

"""
    print(help_string)

#define bpf program
prog = """
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <linux/mutex.h>

//packet header for tcp-------------------
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
//-----------------------------------------

//packet header for udp--------------------
struct vr_udp {
    unsigned short udp_sport;
    unsigned short udp_dport;
    unsigned short udp_length;
    unsigned short udp_csum;
};
//-----------------------------------------
//packet header----------------------------
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
//-----------------------------------------

//output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    __u32 saddr;
    __u32 daddr;
    __u8 protocol;
    __u32 sport;
    __u32 dport;
    int stack_id;
    int ret;
    int trace_val;
    int return_val;
};

//BPF_HASH(stack_map, u32, int, 1024);
BPF_HASH(trace_map, u32, int, 1024);
BPF_STACK_TRACE(stack_trace, 1024);
BPF_PERF_OUTPUT(events);

int probe_handler(struct pt_regs *ctx) {
    int zero = 0, one = 1, mone = -1;
    struct data_t data = {};
    struct vr_packet p = {};
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read(&p, sizeof(p), (void *)PT_REGS_PARM2(ctx));
    data.pid = bpf_get_current_pid_tgid();
    data.ret = 0;
    data.stack_id = stack_trace.get_stackid(ctx, BPF_F_REUSE_STACKID);
    data.ts = bpf_ktime_get_ns();
    int *val = trace_map.lookup_or_init(&data.pid, &zero);
    data.trace_val = *val;
    if(*val == -1) {
       events.perf_submit(ctx, &data, sizeof(data));
       return 0;
    }
    struct iphdr *ih = (struct iphdr *)(p.vp_head+p.vp_network_h);
    struct iphdr iph = {};
    bpf_probe_read(&iph, sizeof(iph), ih);
    data.saddr = iph.saddr;
    data.daddr = iph.daddr;

     data.protocol = iph.protocol;
     if(data.protocol == 6) {
         struct vr_tcp *tcph = (struct vr_tcp *)(p.vp_head+p.vp_data);
         struct vr_tcp tcp = {};
         bpf_probe_read(&tcp, sizeof(tcp), tcph);
         data.sport = tcp.tcp_sport;
         data.dport = tcp.tcp_dport;
     }
     else if(data.protocol == 17) {
         struct vr_udp *udph = (struct vr_udp *)(p.vp_head+p.vp_data);
         struct vr_udp udp = {};
         bpf_probe_read(&udp, sizeof(udp), udph);
         data.sport = udp.udp_sport;
         data.dport = udp.udp_dport;
     }
"""

command_arguments = sys.argv[1:]
file_name = ""
return_flag = False
help_flag = False
arguments = []
i = 0
while(i < len(command_arguments)):
    if command_arguments[i] == "-h" or command_arguments[i] == "-help":
       print_help()
       help_flag = True
       break
    if command_arguments[i] == "-f":
       file_name = command_arguments[i+1]
       i = i+1
    elif command_arguments[i] == "-r":
       return_flag = True;
    elif command_arguments[i] == "-a":
       arguments = command_arguments[i+1:]
       break
    i = i+1

for argument in arguments:
    arg_name, arg_val = argument.split("=")
    FILTER = int(netaddr.IPAddress('.'.join(arg_val.split('.')[::-1])))
    if arg_name == "src":
        prog += """
        if(data.saddr != 0) {
            if(data.saddr == """+str(FILTER)+""") {
                trace_map.update(&data.pid, &one);
                data.trace_val = 1;
            }
            else {
                trace_map.update(&data.pid, &mone);
                data.trace_val = -1;
                events.perf_submit(ctx, &data, sizeof(data));
            }
        }
        """
    elif arg_name == "dest":
        arg_name, arg_val = argument.split("=")
        FILTER = int(netaddr.IPAddress('.'.join(arg_val.split('.')[::-1])))
        prog += """
        if(data.trace_val == 1) {
            if(data.daddr != 0) {
                if(data.daddr == """+str(FILTER)+""") {
                    trace_map.update(&data.pid, &one);
                    data.trace_val = 1;
                }
                else {
                    trace_map.update(&data.pid, &mone);
                    data.trace_val = -1;
                    events.perf_submit(ctx, &data, sizeof(data));
                }
            }
        }
        """
    elif arg_name == "protocol":
        arg_name, arg_val = argument.split("=")
        prog += """
        if(data.trace_val == 1) {
            if(data.protocol != 0) {
                if(data.protocol == """+str(arg_val)+""") {
                    trace_map.update(&data.pid, &one);
                    data.trace_val = 1;
                }
                else {
                    trace_map.update(&data.pid, &mone);
                    data.trace_val = -1;
                    events.perf_submit(ctx, &data, sizeof(data));
                }
            }
        }
        """
    elif arg_name == "sport":
        arg_name, arg_val = argument.split("=")
        prog += """
        if(data.trace_val == 1) {
            if(data.sport != 0) {
                if(data.sport == """+str(arg_val)+""") {
                    trace_map.update(&data.pid, &one);
                    data.trace_val = 1;
                }
                else {
                    trace_map.update(&data.pid, &mone);
                    data.trace_val = -1;
                    events.perf_submit(ctx, &data, sizeof(data));
                }
            }
        }
        """
    elif arg_name == "dport":
        arg_name, arg_val = argument.split("=")
        prog += """
        if(data.trace_val == 1) {
            if(data.dport != 0) {
                if(data.dport == """+str(arg_val)+""") {
                    trace_map.update(&data.pid, &one);
                    data.trace_val = 1;
                }
                else {
                    trace_map.update(&data.pid, &mone);
                    data.trace_val = -1;
                    events.perf_submit(ctx, &data, sizeof(data));
                }
            }
        }
        """
if len(arguments) == 0:
    prog += """
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""
else:
    prog += """
    int *tval = trace_map.lookup_or_init(&data.pid, &zero);

    if(*tval == 0 || *tval == 1) {
         data.trace_val = *tval;
         events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}"""

prog += """
 int ret_probe_handler(struct pt_regs *ctx) {
     int zero = 0;
     struct data_t data = {};
     data.return_val = PT_REGS_RC(ctx);
     data.pid = bpf_get_current_pid_tgid();
     data.ts = bpf_ktime_get_ns();
     bpf_get_current_comm(&data.comm, sizeof(data.comm));
     data.ret = 1;
 """
if len(arguments) == 0:
    prog += """
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
    }
    """
else:
    prog += """
     int *tval = trace_map.lookup_or_init(&data.pid, &zero);
     bpf_trace_printk("ret %d ret_tr %d\\n", *tval, data.ret);
     if(*tval == -1) {
       data.trace_val = *tval;
       events.perf_submit(ctx, &data, sizeof(data));
       return 0;
     }
     if(*tval == 0 || *tval == 1) {
        data.trace_val = *tval;
        events.perf_submit(ctx, &data, sizeof(data));
      }
     return 0;
 }
 """

# load BPF program
b = BPF(text=prog)
if help_flag == False:
   f = open(file_name, "r")
   for line in f:
       line = line.strip()
       b.attach_kprobe(event=line, fn_name="probe_handler")
       b.attach_kretprobe(event=line, fn_name="ret_probe_handler")


 # define output data structure in Python
TASK_COMM_LEN = 16
class Data(ct.Structure):
    _fields_ = [("pid", ct.c_uint),
                ("ts", ct.c_ulonglong),
                ("comm", ct.c_char * TASK_COMM_LEN), ("saddr", ct.c_uint), ("daddr", ct.c_uint), ("protocol", ct.c_uint), ("sport", ct.c_uint), ("dport", ct.c_uint),
                ("stack_id", ct.c_uint), ("ret", ct.c_int), ("trace_val", ct.c_int), ("return_val", ct.c_int)]

# header
if help_flag == False:
   print("%-15s %-11s %-10s %-15s %-10s %-12s %-10s %-18s %s" % ("TIME(S)", "COMM", "PID", "saddr", "daddr", "protocol", "sport", "dport", "Trace"))

start = 0
trace_map = b.get_table("trace_map")
fmap = dict()
indent = dict()
stack_trace = b.get_table("stack_trace")
def print_event(cpu, data, size):
    global start
    global indent
    event = ct.cast(data, ct.POINTER(Data)).contents
    if event.pid not in indent:
       indent[event.pid] = "   "
    if event.trace_val == -1:
       if event.ret == 0:
          indent[event.pid] += "   "
       elif event.ret == 1:
          indent[event.pid] = indent[event.pid][:-3]
       fmap.pop(event.pid, None)

       if indent[event.pid] == "   ":
          trace_map.pop(ct.c_uint(event.pid), None)
       return;

    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000

    function = "%-13.9f %-12s %-10d %-15s %-15s %-10d %-10d %-10d" % (time_s, event.comm, event.pid,
                inet_ntop(AF_INET, pack("I", event.saddr)), inet_ntop(AF_INET, pack("I", event.daddr)), event.protocol, event.sport, event.dport)
    ret_val = ""

    if event.ret == 0:
        for addr in stack_trace.walk(event.stack_id):
            function = function + indent[event.pid] + b.ksym(addr, event.pid, show_offset=True)
            indent[event.pid] += "   "
            break
        if event.pid not in fmap:
           fmap[event.pid] = function +" {\n"
        else:
           fmap[event.pid] = fmap[event.pid] + function + " {\n"
    else:
        indent[event.pid] = indent[event.pid][:-3]
        if event.pid in fmap:
           if return_flag == True:
              ret_val = str(event.return_val)
           fmap[event.pid] = fmap[event.pid] + function + indent[event.pid] + "}" + " " +"return value: "+ ret_val + "\n"

    if indent[event.pid] == "   ":
       if len(arguments) == 0:
           print(fmap[event.pid])
           fmap.pop(event.pid, None)
       elif event.trace_val == 1:
          print(fmap[event.pid])
          fmap.pop(event.pid, None)
          trace_map.pop(ct.c_uint(event.pid), None)

if help_flag == False:
   b["events"].open_perf_buffer(print_event)
   while 1:
      try:
         b.perf_buffer_poll()
      except KeyboardInterrupt:
         exit()
