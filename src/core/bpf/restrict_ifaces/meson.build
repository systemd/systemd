# SPDX-License-Identifier: LGPL-2.1+

restrict_network_interfaces_hexdump_h = custom_target(
    'restrict-ifaces-hexdump.h',
    input : 'restrict-ifaces.bpf.c',
    output : 'restrict-ifaces-hexdump.h',
    command : [build_bpf_py,
            '--clang_exec', clang.path(),
            '--llc_exec', llc.path(),
            '--arch', host_machine.cpu_family(),
            '@INPUT@', '@OUTPUT@'])
