# Packet Tracer Tool 

### Introduction
This tool can be used to trace the kernel execution path in the kernel 'Vrouter' module and can trace the life cycle of a packet. The tool uses the eBPF kprobe tracing framework. Conditional tracing is also possible with this tool by filtering out IPv4 packets based on Source IP address, Destination IP address, Protocol, Source port and Destination port.

### Installation
To run this tool bcc-tools package must be installed on the system. Installation process for various linux releases can be found [here](https://github.com/iovisor/bcc/blob/master/INSTALL.md).
Installed bcc-tools can be found in /usr/share/bcc/tools directory and to verify run any of the existing tools.

### Exceptions
1. Exception: Failed to attach BPF to kprobe
   Make sure both Linux kernel version and kernel-devel versions are same. If not     upgrade kernel to make them same.

### Running Script
The following flags are available while running the script:
| Flag | Function | Description
| -- | -- | -- |
| -f | Filename | Name of the file from symbols are to be traced
| -r | Return value | Print return value of probed functions
| -h or -help | Help | Prints help message
| -a | Arguments | Arguments on basis of which packets are filtered
| -o | Organize | Organize output to form a packet flow  

The arguments that can be provided are:

| Argument | Name
|--|--|
| src | Source IP Address
| dest | Destination IP Address
| protocol | protocol
| sport | Source Port
| dport | Destination Port

Any number of arguments can be provided while tracing and if no arguments are provided then default tracing takes place where packet trace of all packets will be printed.

### Tracing Examples
1. Trace all symbols within func symbol file
 `python pkt_tracer.py -f func`

2. Traces all symbols within func file and also prints the return values from those functions
 `python pkt_tracer.py -f func -r`

3. Traces only those packets whose source IP address is 192.168.100.3
`python pkt_tracer.py -f func -a src=192.168.100.3`

4.  Traces only those packets whose source IP is 192.168.100.3 and destination IP is 192.168.100.4
`python pkt_tracer.py -f func -a src=192.168.100.3 dest=192.168.100.4`

5. Traces only those packets that satisfy all the filters applied
`python pkt_tracer.py -f func -r -o -a src=192.168.100.3 dest=192.168.100.4 protocol=6 sport=4165 dport=16387`



