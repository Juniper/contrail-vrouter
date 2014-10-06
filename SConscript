#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

import subprocess
import sys
import os

AddOption('--kernel-dir', dest = 'kernel-dir', action='store',
          help='Linux kernel source directory for vrouter.ko')

AddOption('--system-header-path', dest = 'system-header-path', action='store',
          help='Linux kernel headers for applications')

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

def shellCommand(cmd):
    """ Return the output of a shell command
        This wrapper is required since check_output is not supported in
        python 2.6
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (output, _) = proc.communicate()
    return output.strip()

if sys.platform.startswith('freebsd'):
    dp_dir = dp_dir + '/freebsd'
    env['ENV']['MAKEOBJDIR'] = dp_dir

if sys.platform != 'darwin':

    install_root = GetOption('install_root')
    if install_root == None:
        install_root = ''

    src_root = install_root + '/usr/src/vrouter/'
    env.Replace(SRC_INSTALL_TARGET = src_root)
    env.Install(src_root, ['LICENSE', 'Makefile', 'GPL-2.0.txt'])
    env.Alias('install', src_root)

    subdirs = ['linux', 'include', 'dp-core', 'host', 'sandesh', 'utils', 'uvrouter']
    for sdir in  subdirs:
        env.SConscript(sdir + '/SConscript',
                       exports='VRouterEnv',
                       variant_dir = env['TOP'] + '/vrouter/' + sdir,
                       duplicate = 0)

    make_cmd = 'make'
    if GetOption('kernel-dir'):
        make_cmd += ' KERNELDIR=' + GetOption('kernel-dir')
    make_cmd += ' SANDESH_HEADER_PATH=' + Dir(env['TOP'] + '/vrouter/').abspath
    make_cmd += ' SANDESH_SRC_ROOT=' + '../build/kbuild/'
    make_cmd += ' SANDESH_EXTRA_HEADER_PATH=' + Dir('#tools/').abspath
    if 'vrouter' in COMMAND_LINE_TARGETS:
        BUILD_TARGETS.append('vrouter/uvrouter')
        BUILD_TARGETS.append('vrouter/utils')

    kern = env.Command('vrouter.ko', makefile, make_cmd, chdir=dp_dir)
    env.Default(kern)

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

    if GetOption('clean') and (not COMMAND_LINE_TARGETS or 'vrouter' in COMMAND_LINE_TARGETS):
        os.system('cd ' + dp_dir + ';' + make_cmd + ' clean')

    if GetOption('kernel-dir'):
        kern_version = shellCommand(
            'cat %s/include/config/kernel.release' % GetOption('kernel-dir'))
    else:
        kern_version = shellCommand('uname -r')

    kern_version = kern_version.strip()
    libmod_dir = install_root
    libmod_dir += '/lib/modules/%s/extra/net/vrouter' % kern_version
    env.Alias('build-kmodule', env.Install(libmod_dir, kern))

# Local Variables:
# mode: python
# End:
