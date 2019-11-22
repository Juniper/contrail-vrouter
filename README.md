# contrail-vrouter

Contrail Virtual Router

The Contrail Virtual Router implements the data-plane functionality that allows a virtual interface to be associated
with a [VRF](http://en.wikipedia.org/wiki/Virtual_Routing_and_Forwarding).

The Contrail Virtual Router is distributed under the terms of the BSD 2-Clause License and the GPLv2.

The implementation is split into a generic "dp-core" directory used by
multiple operating systems and OS-specific glue. The "linux" directory
contains the Linux specific code.

The utils directory contains user space applications that can be used
to created interfaces (utils/vif) or display the state of the kernel
module.

# building vrouter.ko for a specific OS

### For contrail-version < 5.0

1. Initialize the respository from Juniper/contrail-vnc-private. The following example is to initialize repository for contrail-4.1 on redhat.
`$ repo init -u git@github.com:Juniper/contrail-vnc-private -R4.1/redhat70/manifest-newton.xml`

2. Sync the repo. This will fetch vrouter, build and sandesh repositories.
`$ repo sync`

2. Execute fetch_packages.py from contrail-webui-third-party, third_party, distro/third_party.
> cd third_party/
`python fetch_packages.py`
cd distro/third_party/
`python fetch_packages.py`
cd contrail-webui-third-party/
`python fetch_packages.py`

4. Build vrouter
`$ scons vrouter`

### For contrail-version >= 5.0
1. Contrail-dev-env container process can be followed to build a vrouter.ko module which can be found [here](https://github.com/Juniper/contrail-dev-env).
