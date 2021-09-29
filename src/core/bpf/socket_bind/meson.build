# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('BPF_FRAMEWORK') == 1
        socket_bind_skel_h = custom_target(
                'socket-bind.skel.h',
                input : 'socket-bind.bpf.c',
                output : 'socket-bind.skel.h',
                command : [build_bpf_skel_py,
                           '--clang_exec', clang.path(),
                           '--llvm_strip_exec', llvm_strip.path(),
                           '--bpftool_exec', bpftool.path(),
                           '--arch', host_machine.cpu_family(),
                           '@INPUT@', '@OUTPUT@'])
endif
