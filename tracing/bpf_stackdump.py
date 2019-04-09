from bcc import BPF
import ctypes as ct
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import struct
import socket
import sys
import ipaddress as ip
import netaddr

prog = """
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <linux/mutex.h>


//output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    int stack_id;
    int ret;
};

BPF_STACK_TRACE(stack_trace, 1024);
BPF_PERF_OUTPUT(events);

int probe_handler(struct pt_regs *ctx) {
struct data_t data = {};
data.pid = bpf_get_current_pid_tgid(); 
bpf_get_current_comm(&data.comm, sizeof(data.comm));
data.ts = bpf_ktime_get_ns();
data.stack_id = stack_trace.get_stackid(ctx, BPF_F_REUSE_STACKID);
events.perf_submit(ctx, &data, sizeof(data));
return 0;
}
"""


b = BPF(text=prog)
b.attach_kprobe(event="vr_flow_forward", fn_name="probe_handler")
stack_trace = b.get_table("stack_trace")

TASK_COMM_LEN = 16
class Data(ct.Structure):
     _fields_ = [("pid", ct.c_uint),
                ("ts", ct.c_ulonglong),
                ("comm", ct.c_char * TASK_COMM_LEN),
                ("stack_id", ct.c_uint), ("ret", ct.c_int)]

print("%-15s %-11s %-10s" % ("TIME(S)", "COMM", "PID"))
start = 0

def print_event(cpu, data, size):
    global start
    event = ct.cast(data, ct.POINTER(Data)).contents
    if start == 0:
       start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-13.9f %-12s %-10d\n" %(time_s, event.comm, event.pid))
  
    print("Kernel Stack")
    for addr in stack_trace.walk(event.stack_id):
        print(b.ksym(addr, event.pid, show_offset=True))
    print("------------------------------------------------------------")
b["events"].open_perf_buffer(print_event)
while 1:
  try:
     b.perf_buffer_poll()
  except KeyboardInterrupt:
     exit()

