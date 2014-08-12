contrail-vrouter
================

Contrail Virtual Router

The Contrail Virtual Router implements the data-plane functionality that allows a virtual interface to be associated
with a [VRF](http://en.wikipedia.org/wiki/Virtual_Routing_and_Forwarding).

The Contrail Virtual Router is distributed under the terms of the BSD 2-Clause License and the GPLv2.

The implementation is split into a generic "dp-core" directory used by
multiple operating systems and OS-specific glue. The "linux" directory
contains the Linux specific code.

The code has been tested with both 2.6.32 and 3.0 kernel series and
with both KVM and Xen as hypervisors.

The utils directory contains user space applications that can be used
to created interfaces (utils/vif) or display the state of the kernel
module.

building vrouter.ko for a specific OS
==================================

1. Initialize the repository
$ repo init -u git@github.com:Juniper/contrail-vnc -m vrouter-manifest.xml

2. Sync the repo. This will fetch vrouter, build and sandesh repositories.
$ repo sync

3. Build vrouter
$ scons vrouter

