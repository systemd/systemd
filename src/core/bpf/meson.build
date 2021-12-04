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

        bpf_o_unstripped_cmd = [
                clang,
                clang_flags,
                clang_arch_flag,
                '-I.'
        ]

        if not meson.is_cross_build()
                target_triplet_cmd = run_command('gcc', '-dumpmachine', check: false)
                if target_triplet_cmd.returncode() == 0
                        target_triplet = target_triplet_cmd.stdout().strip()
                        bpf_o_unstripped_cmd += [
                                '-isystem',
                                '/usr/include/@0@'.format(target_triplet)
                        ]
                endif
        endif

        bpf_o_unstripped_cmd += [
                '-idirafter',
                libbpf_include_dir,
                '@INPUT@',
                '-o',
                '@OUTPUT@'
        ]

        bpf_o_cmd = [
                llvm_strip,
                '-g',
                '@INPUT@',
                '-o',
                '@OUTPUT@'
        ]

        skel_h_cmd = [
                bpftool,
                'g',
                's',
                '@INPUT@'
        ]
endif
