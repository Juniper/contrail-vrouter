#
# Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
#

import subprocess
import sys
import os
import copy

AddOption('--kernel-dir', dest = 'kernel-dir', action='store',
          help='Linux kernel source directory for vrouter.ko')

AddOption('--system-header-path', dest = 'system-header-path', action='store',
          help='Linux kernel headers for applications')

env = DefaultEnvironment().Clone()
VRouterEnv = env
dpdk_exists = os.path.isdir('../third_party/dpdk')

# DPDK build configuration
dpdk_conf = {}
DPDK_TARGET = 'x86_64-native-linuxapp-gcc'
DPDK_SRC_DIR = '#third_party/dpdk/'
DPDK_DST_DIR = env['TOP'] + '/vrouter/dpdk/' + DPDK_TARGET
DPDK_INC_DIR = DPDK_DST_DIR + '/include'
DPDK_LIB_DIR = DPDK_DST_DIR + '/lib'

# Include paths
env.Replace(CPPPATH = '#vrouter/include')
env.Append(CPPPATH = [env['TOP'] + '/vrouter/sandesh/gen-c'])
env.Append(CPPPATH = ['#tools'])
env.Append(CPPPATH = ['#tools/sandesh/library/c'])

vr_root = './'
makefile = vr_root + 'Makefile'
dp_dir = Dir(vr_root).srcnode().abspath + '/'
make_dir = dp_dir

def MakeTestCmdFn(self, env, test_name, test_list, deps):
    sources = copy.copy(deps)
    sources.append(test_name + '.c')
    tgt = env.UnitTest(target = test_name, source = sources)
    env.Alias('vrouter:'+ test_name, tgt)
    test_list.append(tgt)
    return tgt

VRouterEnv.AddMethod(MakeTestCmdFn, 'MakeTestCmd')

def shellCommand(cmd):
    """ Return the output of a shell command
        This wrapper is required since check_output is not supported in
        python 2.6
    """
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    (output, _) = proc.communicate()
    return output.strip()

if sys.platform.startswith('freebsd'):
    make_dir = make_dir + '/freebsd'
    env['ENV']['MAKEOBJDIR'] = make_dir

if sys.platform != 'darwin':

    install_root = GetOption('install_root')
    if install_root == None:
        install_root = ''

    src_root = install_root + '/usr/src/vrouter/'
    env.Replace(SRC_INSTALL_TARGET = src_root)
    env.Install(src_root, ['LICENSE', 'Makefile', 'GPL-2.0.txt'])
    env.Alias('install', src_root)

    buildinfo = env.GenerateBuildInfoCCode(target = ['vr_buildinfo.c'],
            source = [], path = dp_dir + 'dp-core')

    subdirs = ['linux', 'include', 'dp-core', 'host', 'sandesh', \
                        'utils', 'uvrouter', 'test']
    if dpdk_exists:
        subdirs.append('dpdk')
        #
        # DPDK libraries need to be linked as a whole archive, otherwise some
        # callbacks and constructors will not be linked in. Also some of the
        # libraries need to be linked as a group for the cross-reference resolving.
        #
        # That is why we pass DPDK libraries as flags to the linker.
        #
        # Order is important: from higher level to lower level
        # The list is from the rte.app.mk file
        DPDK_LIBS = [
            '-Wl,--whole-archive',
        #    '-lrte_distributor',
        #    '-lrte_reorder',
            '-lrte_kni',
        #    '-lrte_ivshmem',
        #    '-lrte_pipeline',
        #    '-lrte_table',
            '-lrte_port',
            '-lrte_timer',
            '-lrte_hash',
        #    '-lrte_jobstats',
        #    '-lrte_lpm',
        #    '-lrte_power',
        #    '-lrte_acl',
        #    '-lrte_meter',
            '-lrte_sched',
            '-lm',
            '-lrt',
        #    '-lrte_vhost',
        #    '-lpcap',
        #    '-lfuse',
        #    '-libverbs',
            '-Wl,--start-group',
            '-lrte_kvargs',
            '-lrte_mbuf',
            '-lrte_ip_frag',
            '-lethdev',
            '-lrte_malloc',
            '-lrte_mempool',
            '-lrte_ring',
            '-lrte_eal',
            '-lrte_cmdline',
        #    '-lrte_cfgfile',
            '-lrte_pmd_bond',
        #    '-lrte_pmd_xenvirt',
        #    '-lxenstore',
        #    '-lrte_pmd_vmxnet3_uio',
        #    '-lrte_pmd_virtio_uio',
        #    '-lrte_pmd_enic',
            '-lrte_pmd_i40e',
        #    '-lrte_pmd_fm10k',
            '-lrte_pmd_ixgbe',
            '-lrte_pmd_e1000',
        #    '-lrte_pmd_mlx4',
        #    '-lrte_pmd_ring',
        #    '-lrte_pmd_pcap',
        #    '-lrte_pmd_af_packet',
            '-Wl,--end-group',
            '-Wl,--no-whole-archive'
        ]

        # Pass -g and -O flags if present to DPDK
        DPDK_FLAGS = ' '.join(o for o in env['CCFLAGS'] if ('-g' in o or '-O' in o))

        # Make DPDK
        dpdk_src_dir = Dir(DPDK_SRC_DIR).abspath
        dpdk_dst_dir = Dir(DPDK_DST_DIR).abspath

        make_cmd = 'make -C ' + dpdk_src_dir \
            + ' EXTRA_CFLAGS="' + DPDK_FLAGS + '"' \
            + ' O=' + dpdk_dst_dir \
            + ' '
        dpdk_lib = env.Command('dpdk_lib', None,
            make_cmd + 'config T=' + DPDK_TARGET
            + ' && ' + make_cmd)

        env.Append(CPPPATH = DPDK_INC_DIR);
        env.Append(LIBPATH = DPDK_LIB_DIR)
        env.Append(DPDK_LINKFLAGS = DPDK_LIBS)

        if GetOption('clean'):
            os.system(make_cmd + 'clean')

    for sdir in subdirs:
        env.SConscript(sdir + '/SConscript',
                       exports='VRouterEnv dpdk_lib',
                       variant_dir = env['TOP'] + '/vrouter/' + sdir,
                       duplicate = 0)

    make_cmd = 'cd ' + make_dir + ' && make'
    if GetOption('kernel-dir'):
        make_cmd += ' KERNELDIR=' + GetOption('kernel-dir')
    make_cmd += ' SANDESH_HEADER_PATH=' + Dir(env['TOP'] + '/vrouter/').abspath
    make_cmd += ' SANDESH_SRC_ROOT=' + '../build/kbuild/'
    make_cmd += ' SANDESH_EXTRA_HEADER_PATH=' + Dir('#tools/').abspath
    if 'vrouter' in COMMAND_LINE_TARGETS:
        BUILD_TARGETS.append('vrouter/uvrouter')
        if dpdk_exists:
            BUILD_TARGETS.append('vrouter/dpdk')
        BUILD_TARGETS.append('vrouter/utils')

    kern = env.Command('vrouter.ko', None, make_cmd)
    env.Default(kern)
    env.AlwaysBuild(kern)

    env.Depends(kern, buildinfo)
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
        os.system(make_cmd + ' clean')

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
