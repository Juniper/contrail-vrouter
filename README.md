# contrail-vrouter

Contrail Virtual Router

The Contrail Virtual Router implements the data-plane functionality that allows a virtual interface to be associated
with a [VRF](http://en.wikipedia.org/wiki/Virtual_Routing_and_Forwarding).

The Contrail Virtual Router is distributed under the terms of the BSD 2-Clause License and the GPLv2.

The implementation is split into generic "dp-core" and "dpdk" directories used by
multiple operating systems and OS-specific glue. The "linux" directory contains the
Linux specific code.

The utils directory contains user space applications that can be used
to created interfaces (utils/vif) or display the state of the kernel
module.

# building vrouter.ko and contrail-vrouter-dpdk for a specific OS

1. Contrail-dev-env container process can be followed to build vrouter.ko module and contrail-vrouter-dpdk binary,
   which can be found [here](https://github.com/Juniper/contrail-dev-env).
