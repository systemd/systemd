# SPDX-License-Identifier: LGPL-2.1+

allow_bind_skel_h = custom_target(
        'allow-bind-skel.h',
        input : 'allow-bind.bpf.c',
        output : 'allow-bind-skel.h',
        command : [build_bpf_skel_py,
                '--clang_exec', clang.path(),
                '--llvm_strip_exec', llvm_strip.path(),
                '--bpftool_exec', bpftool.path(),
                '--arch', host_machine.cpu_family(),
                '@INPUT@', '@OUTPUT@'])
