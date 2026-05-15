# SPDX-License-Identifier: LGPL-2.1-or-later

if not libbpf.found()
        conf.set10('BPF_FRAMEWORK', false)
else
        clang_found = false
        clang_supports_bpf = false
        bpf_gcc_found = false
        bpftool_strip = false
        deps_found = false

        if bpf_compiler == 'clang'
                # Support 'versioned' clang/llvm-strip binaries, as seen on Debian/Ubuntu
                # (like clang-10/llvm-strip-10)
                if meson.is_cross_build() or cc.get_id() != 'clang' or cc.cmd_array()[0].contains('afl-clang') or cc.cmd_array()[0].contains('hfuzz-clang')
                        r = find_program('clang',
                                         required : bpf_framework,
                                         version : '>= 10.0.0')
                        clang_found = r.found()
                        if clang_found
                                clang = r.full_path()
                        endif
                else
                        clang_found = true
                        clang = cc.cmd_array()
                endif

                if clang_found
                        # Check if 'clang -target bpf' is supported.
                        clang_supports_bpf = run_command(clang, '-target', 'bpf', '--print-supported-cpus', check : false).returncode() == 0
                endif
                if bpf_framework.enabled() and not clang_supports_bpf
                        error('bpf-framework was enabled but clang does not support bpf')
                endif
        elif bpf_compiler == 'gcc'
                bpf_gcc = find_program('bpf-gcc',
                                       'bpf-none-gcc',
                                       'bpf-unknown-none-gcc',
                                       required : true,
                                       version : '>= 13.1.0')
                bpf_gcc_found = bpf_gcc.found()
        endif

        if clang_supports_bpf or bpf_gcc_found
                # Debian installs this in /usr/sbin/ which is not in $PATH.
                # We check for 'bpftool' first, honouring $PATH, and in /usr/sbin/ for Debian.
                # We use 'bpftool gen object' subcommand for bpftool strip, it was added by d80b2fcbe0a023619e0fc73112f2a02c2662f6ab (v5.13).
                bpftool = find_program('bpftool',
                                       '/usr/sbin/bpftool',
                                       required : bpf_framework.enabled() and bpf_compiler == 'gcc',
                                       version : bpf_compiler == 'gcc' ? '>= 7.0.0' : '>= 5.13.0')

                if bpftool.found()
                        bpftool_strip = true
                        deps_found = true
                elif bpf_compiler == 'clang'
                        # We require the 'bpftool gen skeleton' subcommand, it was added by 985ead416df39d6fe8e89580cc1db6aa273e0175 (v5.6).
                        bpftool = find_program('bpftool',
                                               '/usr/sbin/bpftool',
                                               required : bpf_framework,
                                               version : '>= 5.6.0')
                endif

                # We use `llvm-strip` as a fallback if `bpftool gen object` strip support is not available.
                if not bpftool_strip and bpftool.found() and clang_supports_bpf
                        if not meson.is_cross_build()
                                llvm_strip_bin = run_command(clang, '--print-prog-name', 'llvm-strip',
                                                             check : true).stdout().strip()
                        else
                                llvm_strip_bin = 'llvm-strip'
                        endif
                        llvm_strip = find_program(llvm_strip_bin,
                                                  required : bpf_framework,
                                                  version : '>= 10.0.0')
                        deps_found = llvm_strip.found()
                endif
        endif

        # Can build BPF program from source code in restricted C
        conf.set10('BPF_FRAMEWORK', deps_found)
endif

if conf.get('BPF_FRAMEWORK') == 1
        bpf_clang_flags = [
                '-std=gnu17',
                '-Wno-compare-distinct-pointer-types',
                '-Wno-microsoft-anon-tag',
                '-fms-extensions',
                '-fno-stack-protector',
                '-O2',
                '-target',
                'bpf',
                '-g',
                '-c',
        ]

        bpf_gcc_flags = [
                '-std=gnu17',
                '-fms-extensions',
                '-fno-stack-protector',
                '-fno-ssa-phiopt',
                '-O2',
                '-mcpu=v3',
                '-mco-re',
                '-gbtf',
                '-c',
        ]

        # If c_args contains these flags copy them along with the values, in order to avoid breaking
        # reproducible builds and other functionality
        propagate_cflags = [
                '-ffile-prefix-map=',
                '-fdebug-prefix-map=',
                '-fmacro-prefix-map=',
                '--sysroot=',
        ]

        foreach opt : c_args
                foreach flag : propagate_cflags
                        if opt.startswith(flag)
                                bpf_clang_flags += [opt]
                                bpf_gcc_flags += [opt]
                                break
                        endif
                endforeach
        endforeach

        # Generate defines that are appropriate to tell the compiler what architecture
        # we're compiling for. By default we just map meson's cpu_family to __<cpu_family>__.
        # This dictionary contains the exceptions where this doesn't work.
        #
        # C.f. https://mesonbuild.com/Reference-tables.html#cpu-families
        # and src/basic/missing_syscall_def.h.

        # Start with older ABI. When define is missing, we're likely targeting that.
        ppc64_elf_version = '1'

        if host_machine.cpu_family() == 'ppc64'
                # cc doesn't have to be bpf_compiler, but they should be targeting the same ABI
                call_elf_value = cc.get_define('_CALL_ELF')
                if call_elf_value != ''
                        ppc64_elf_version = call_elf_value
                endif
        endif

        cpu_arch_defines = {
                'ppc'         : ['-D__powerpc__', '-D__TARGET_ARCH_powerpc'],
                'ppc64'       : ['-D__powerpc64__', '-D__TARGET_ARCH_powerpc', '-D_CALL_ELF=' + ppc64_elf_version],
                'riscv32'     : ['-D__riscv', '-D__riscv_xlen=32', '-D__TARGET_ARCH_riscv'],
                'riscv64'     : ['-D__riscv', '-D__riscv_xlen=64', '-D__TARGET_ARCH_riscv'],
                'x86'         : ['-D__i386__', '-D__TARGET_ARCH_x86'],
                's390x'       : ['-D__s390__', '-D__s390x__', '-D__TARGET_ARCH_s390'],

                # For arm, assume hardware fp is available.
                'arm'         : ['-D__arm__', '-D__ARM_PCS_VFP', '-D__TARGET_ARCH_arm'],
                'loongarch64' : ['-D__loongarch__', '-D__loongarch_grlen=64', '-D__TARGET_ARCH_loongarch']
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

        bpf_o_unstripped_cmd += ['-I.', '-include', 'config.h']

        if cc.get_id() == 'gcc' or meson.is_cross_build()
                if cc.get_id() != 'gcc'
                        warning('Cross compiler is not gcc. Guessing the target triplet for bpf likely fails.')
                endif
                target_triplet_cmd = run_command(cc.cmd_array(), '-print-multiarch', check: false)
        else
                # clang does not support -print-multiarch (D133170) and its -dump-machine
                # does not match multiarch. Query gcc instead.
                target_triplet_cmd = run_command('gcc', '-print-multiarch', check: false)
        endif
        if target_triplet_cmd.returncode() == 0
                sysroot = meson.get_external_property('sys_root', '/')
                target_triplet = target_triplet_cmd.stdout().strip()
                target_include_dir = sysroot / 'usr' / 'include'
                target_triple_include_dir = target_include_dir / target_triplet
                isystem_dir = ''
                if fs.is_dir(target_triple_include_dir)
                        isystem_dir = target_triple_include_dir
                elif fs.is_dir(target_include_dir)
                        isystem_dir = target_include_dir
                endif
                if isystem_dir != ''
                        bpf_o_unstripped_cmd += [
                                '-isystem', isystem_dir
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
endif

use_provided_vmlinux_h = false
use_generated_vmlinux_h = false
provided_vmlinux_h_path = get_option('vmlinux-h-path')

# For the more complex BPF programs we really want a vmlinux.h (which is arch
# specific, but only somewhat bound to kernel version). Ideally the kernel
# development headers would ship that, but right now they don't. Hence address
# this in two ways:
#
# 1. Provide a vmlinux.h at build time
# 2. Generate the file on the fly where possible (which requires /sys/ to be mounted)
#
# We generally prefer the former (to support reproducible builds), but will
# fallback to the latter.

if conf.get('BPF_FRAMEWORK') == 1
        enable_vmlinux_h = get_option('vmlinux-h')

        if enable_vmlinux_h == 'auto'
                if provided_vmlinux_h_path != ''
                        use_provided_vmlinux_h = true
                elif fs.exists('/sys/kernel/btf/vmlinux') and \
                                bpftool.found() and \
                                (host_machine.cpu_family() == build_machine.cpu_family()) and \
                                host_machine.cpu_family() in ['x86_64', 'aarch64']

                        # We will only generate a vmlinux.h from the running
                        # kernel if the host and build machine are of the same
                        # family. Also for now we focus on x86_64 and aarch64,
                        # since other archs don't seem to be ready yet.

                        use_generated_vmlinux_h = true
                endif
        elif enable_vmlinux_h == 'provided'
                use_provided_vmlinux_h = true
        elif enable_vmlinux_h == 'generated'
                if not fs.exists('/sys/kernel/btf/vmlinux')
                        error('BTF data from kernel not available (/sys/kernel/btf/vmlinux missing), cannot generate vmlinux.h, but was asked to.')
                endif
                if not bpftool.found()
                        error('bpftool not available, cannot generate vmlinux.h, but was asked to.')
                endif
                use_generated_vmlinux_h = true
        endif
endif

vmlinux_h_dependency = []
if use_provided_vmlinux_h
        if not fs.exists(provided_vmlinux_h_path)
                error('Path to provided vmlinux.h does not exist.')
        endif
        bpf_o_unstripped_cmd += ['-I' + fs.parent(provided_vmlinux_h_path)]
        message(f'Using provided @provided_vmlinux_h_path@')
elif use_generated_vmlinux_h
        vmlinux_h_dependency = custom_target(
                output: 'vmlinux.h',
                command : [ bpftool, 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'c' ],
                capture : true)

        bpf_o_unstripped_cmd += ['-I' + fs.parent(vmlinux_h_dependency.full_path())]
        generated_sources += vmlinux_h_dependency
        message('Using generated @0@'.format(vmlinux_h_dependency.full_path()))
else
        message('Using neither provided nor generated vmlinux.h, some features will not be available.')
endif

conf.set10('HAVE_VMLINUX_H', use_provided_vmlinux_h or use_generated_vmlinux_h)

# 'enum lsm_integrity_type' was added together with the bdev_setintegrity LSM
# hook in kernel commit 2deeb6c333e5 (v6.5). The generated vmlinux.h reflects
# the running kernel's BTF; a provided vmlinux.h can be older, so probe.
have_lsm_integrity_type = false
if use_generated_vmlinux_h
        have_lsm_integrity_type = true
elif use_provided_vmlinux_h
        have_lsm_integrity_type = cc.compiles(
                '#include "@0@"\nenum lsm_integrity_type _t;\n'.format(provided_vmlinux_h_path),
                name : 'enum lsm_integrity_type in vmlinux.h')
endif
conf.set10('HAVE_LSM_INTEGRITY_TYPE', have_lsm_integrity_type)

conf.set10('ENABLE_SYSCTL_BPF', conf.get('HAVE_VMLINUX_H') == 1 and libbpf.version().version_compare('>= 0.7'))

bpf_programs = [
        {
                'source' : files('bind-iface.bpf.c'),
                'condition' : 'BPF_FRAMEWORK',
        },
        {
                'source' : files('restrict-fsaccess.bpf.c'),
                'condition' : 'HAVE_LSM_INTEGRITY_TYPE',
                'depends' : vmlinux_h_dependency,
        },
        {
                'source' : files('restrict-fs.bpf.c'),
                'condition' : 'BPF_FRAMEWORK',
        },
        {
                'source' : files('restrict-ifaces.bpf.c'),
                'condition' : 'BPF_FRAMEWORK',
        },
        {
                'source' : files('socket-bind.bpf.c'),
                'condition' : 'BPF_FRAMEWORK',
        },
        {
                'source' : files('sysctl-monitor.bpf.c'),
                'condition' : 'ENABLE_SYSCTL_BPF',
                'depends' : vmlinux_h_dependency,
        },
        {
                'source' : files('userns-restrict.bpf.c'),
                'condition' : 'HAVE_VMLINUX_H',
                'depends' : vmlinux_h_dependency,
        },
]

bpf_programs_by_name = {}
bpf_sources = []

foreach program : bpf_programs
        if conf.get(program['condition']) != 1
                continue
        endif

        source = program['source'][0]
        # Strip .bpf.c extension
        name = fs.stem(fs.stem(source))

        bpf_o_unstripped = custom_target(
                input : source,
                output : name + '.bpf.unstripped.o',
                command : bpf_o_unstripped_cmd,
                depends : program.get('depends', []))

        bpf_o = custom_target(
                input : bpf_o_unstripped,
                output : name + '.bpf.o',
                command : bpf_o_cmd)

        skel_h = custom_target(
                input : bpf_o,
                output : name + '.bpf.skel.h',
                command : skel_h_cmd,
                capture : true)

        # The wrapper is written at meson setup time and found via the
        # include path, so we don't need to list it as a build-time source.
        # Keeping it out of bpf_programs_by_name also keeps it out of the
        # clang-tidy per-source test loop, which would otherwise fall back
        # to a BPF compile_commands.json entry (no -Isrc/shared) and fail
        # to resolve bpf-dlopen.h.
        configure_file(
                input : 'bpf-skel-wrapper.h.in',
                output : name + '-skel.h',
                configuration : { 'NAME' : name })

        bpf_programs_by_name += { name : skel_h }
        generated_sources += skel_h
        bpf_sources += source
endforeach

if bpf_sources.length() > 0
        meson.add_postconf_script(
                python,
                files('merge-bpf-compdb.py'),
                bpf_sources,
                '--',
                bpf_o_unstripped_cmd)
endif
