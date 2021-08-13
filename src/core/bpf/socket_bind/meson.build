# SPDX-License-Identifier: LGPL-2.1+

if conf.get('BPF_FRAMEWORK') == 1
        clang_flags = [
                '-Wno-compare-distinct-pointer-types',
                '-O2',
                '-target',
                'bpf',
                '-g',
                '-c',
        ]

        clang_arch_flag = '-D__@0@__'.format(host_machine.cpu_family())

        if meson.version().version_compare('>= 0.58')
                libbpf_include_dir = libbpf.get_variable('includedir')
        else
                libbpf_include_dir = libbpf.get_variable(pkgconfig : 'includedir')
        endif

        socket_bind_bpf_o_unstripped = custom_target(
                'socket-bind.bpf.unstripped.o',
                input : 'socket-bind.bpf.c',
                output : 'socket-bind.bpf.unstripped.o',
                command : [clang,
                           clang_flags,
                           clang_arch_flag,
                           '-I.',
                           '-idirafter',
                           libbpf_include_dir,
                           '@INPUT@',
                           '-o',
                           '@OUTPUT@'])

        socket_bind_bpf_o = custom_target(
                'socket-bind.bpf.o',
                input : socket_bind_bpf_o_unstripped,
                output : 'socket-bind.bpf.o',
                command : [llvm_strip,
                           '-g',
                           '@INPUT@',
                           '-o',
                           '@OUTPUT@'])

        socket_bind_skel_h = custom_target(
                'socket-bind.skel.h',
                input : socket_bind_bpf_o,
                output : 'socket-bind.skel.h',
                command : [bpftool, 'g', 's', '@INPUT@'],
                capture : true)
endif
