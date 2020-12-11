# SPDX-License-Identifier: LGPL-2.1+

restrict_fs_hexdump_h = custom_target(
    'restrict-fs-hexdump.h',
    input : 'restrict-fs.bpf.c',
    output : 'restrict-fs-hexdump.h',
    command : [build_bpf_py,
            '--clang_exec', clang.path(),
            '--llc_exec', llc.path(),
            '--arch', 'x86_64',
            '@INPUT@', '@OUTPUT@'])
