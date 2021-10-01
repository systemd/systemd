# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('BPF_FRAMEWORK') == 1
        restrict_ifaces_skel_h = custom_target(
                'restrict-ifaces.skel.h',
                input : 'restrict-ifaces.bpf.c',
                output : 'restrict-ifaces.skel.h',
                command : [build_bpf_skel_py,
                           '--clang_exec', clang.path(),
                           '--llvm_strip_exec', llvm_strip.path(),
                           '--bpftool_exec', bpftool.path(),
                           '--arch', host_machine.cpu_family(),
                           '@INPUT@', '@OUTPUT@'])
endif
