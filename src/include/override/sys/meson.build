# SPDX-License-Identifier: LGPL-2.1-or-later

arch_list = [
        'alpha',
        'arc',
        'arm',
        'arm64',
        'i386',
        'ia64',
        'loongarch64',
        'm68k',
        'mips64',
        'mips64n32',
        'mipso32',
        'parisc',
        'powerpc',
        'powerpc64',
        'riscv32',
        'riscv64',
        'sh',
        's390',
        's390x',
        'sparc',
        'x86_64'
]

run_target(
        'update-syscall-tables',
        command : [update_syscall_tables_sh, meson.current_source_dir()] + arch_list)

syscall_list_txt = files('syscall-list.txt')

syscall_lists = []
foreach arch: arch_list
        # We don't use files() here so that the 'update-syscall-tables' call
        # above can run if arch_list is extended.
        syscall_lists += meson.current_source_dir() / 'syscalls-@0@.txt'.format(arch)
endforeach

generate_syscall_py = find_program('generate-syscall.py')

run_target(
        'update-syscall-header',
        command : [generate_syscall_py, files('syscall.h')] + syscall_lists)
