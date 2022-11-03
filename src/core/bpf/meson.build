# SPDX-License-Identifier: LGPL-2.1+

if conf.get('BPF_FRAMEWORK') != 1
        subdir_done()
endif

bpf_clang_flags = [
        '-std=gnu11',
        '-Wno-compare-distinct-pointer-types',
        '-O2',
        '-target',
        'bpf',
        '-g',
        '-c',
]

bpf_gcc_flags = [
        '-std=gnu11',
        '-O2',
        '-mkernel=5.2',
        '-mcpu=v3',
        '-mco-re',
        '-gbtf',
        '-c',
]

# Generate defines that are appropriate to tell the compiler what architecture
# we're compiling for. By default we just map meson's cpu_family to __<cpu_family>__.
# This dictionary contains the exceptions where this doesn't work.
#
# C.f. https://mesonbuild.com/Reference-tables.html#cpu-families
# and src/basic/missing_syscall_def.h.
cpu_arch_defines = {
        'ppc'     : ['-D__powerpc__'],
        'ppc64'   : ['-D__powerpc64__', '-D_CALL_ELF=2'],
        'riscv32' : ['-D__riscv', '-D__riscv_xlen=32'],
        'riscv64' : ['-D__riscv', '-D__riscv_xlen=64'],
        'x86'     : ['-D__i386__'],

        # For arm, assume hardware fp is available.
        'arm'     : ['-D__arm__', '-D__ARM_PCS_VFP'],
}

bpf_arch_flags = cpu_arch_defines.get(host_machine.cpu_family(),
                                      ['-D__@0@__'.format(host_machine.cpu_family())])
if bpf_compiler == 'gcc'
        bpf_arch_flags += ['-m' + host_machine.endian() + '-endian']
endif

libbpf_include_dir = libbpf.get_variable(pkgconfig : 'includedir')

bpf_o_unstripped_cmd = []
if bpf_compiler == 'clang'
        bpf_o_unstripped_cmd += [
                clang,
                bpf_clang_flags,
                bpf_arch_flags,
        ]
elif bpf_compiler == 'gcc'
        bpf_o_unstripped_cmd += [
                bpf_gcc,
                bpf_gcc_flags,
                bpf_arch_flags,
        ]
endif

bpf_o_unstripped_cmd += ['-I.']

if not meson.is_cross_build() and bpf_compiler == 'clang'
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

if bpftool_strip
        bpf_o_cmd = [
                bpftool,
                'gen',
                'object',
                '@OUTPUT@',
                '@INPUT@'
        ]
elif bpf_compiler == 'clang'
        bpf_o_cmd = [
                llvm_strip,
                '-g',
                '@INPUT@',
                '-o',
                '@OUTPUT@'
        ]
endif

skel_h_cmd = [
        bpftool,
        'gen',
        'skeleton',
        '@INPUT@'
]
