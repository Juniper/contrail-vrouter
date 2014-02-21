#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

import sys
import os
import platform

AddOption('--kernel-dir', dest = 'kernel-dir', action='store',
          help='Linux kernel source directory for vrouter.ko')

env = DefaultEnvironment().Clone()
VRouterEnv = env

# Include paths
env.Replace(CPPPATH = '#vrouter/include')
env.Append(CPPPATH = [env['TOP'] + '/vrouter/sandesh/gen-c'])
env.Append(CPPPATH = ['#tools'])
env.Append(CPPPATH = ['#tools/sandesh/library/c'])

vr_root = './'
makefile = vr_root + 'Makefile'
dp_dir = Dir(vr_root).srcnode().abspath

if sys.platform != 'darwin':
    subdirs = ['dp-core', 'host', 'sandesh', 'utils', 'uvrouter']
    for sdir in  subdirs:
        env.SConscript(sdir + '/SConscript',
                       exports='VRouterEnv',
                       variant_dir = env['TOP'] + '/vrouter/' + sdir,
                       duplicate = 0)

    make_cmd = 'make'
    if platform.system().startswith('Linux'):
       if platform.linux_distribution()[0].startswith('XenServer'):
          make_cmd += ' KERNELDIR=' + os.environ.get('XENBUILDER_KERN_DIR')
       else:
          if GetOption('kernel-dir'):
            make_cmd += ' KERNELDIR=' + GetOption('kernel-dir')
    make_cmd += ' BUILD_DIR=' + Dir(env['TOP']).abspath
    kern = env.Command('vrouter.ko', makefile, make_cmd, chdir=dp_dir)
    env.Default('vrouter.ko')

    env.Depends(kern, env.Install(
            '#build/kbuild/sandesh/gen-c',
            env['TOP'] + '/vrouter/sandesh/gen-c/vr_types.c'))
    sandesh_lib = [
        'protocol/thrift_binary_protocol.c',
        'protocol/thrift_protocol.c',
        'sandesh.c',
        'transport/thrift_fake_transport.c',
        'transport/thrift_memory_buffer.c',
        'transport/thrift_transport.c',
        ]
    for src in sandesh_lib:
        dirname = os.path.dirname(src)
        env.Depends(kern,
                    env.Install(
                '#build/kbuild/sandesh/library/c/' + dirname,
                env['TOP'] + '/tools/sandesh/library/c/' + src))

    if GetOption('clean'):
        os.system('cd ' + dp_dir + '; make clean')

# Local Variables:
# mode: python
# End:
