contrail-vrouter
================

Contrail Virtual Router

The Contrail Virtual Router implements the data-plane functionality that allows a virtual interface to be associated
with a [VRF](http://en.wikipedia.org/wiki/Virtual_Routing_and_Forwarding). The implementation is split into a generic
"dp-core" directory as well as a linux directory which interfaces with the Linux kernel.

While currently only the only supported "hypervisor" is the linux kernel the intent is to be able to use the
"dp-core" module in other configurations in the future.

The code has been tested with both 2.6.32 and 3.0 kernel series and
with both KVM and Xen as hypervisors.

The utils directory contains user space applications that can be used
to created interfaces (utils/vif) or display the state of the kernel
module.
