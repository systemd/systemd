# SPDX-License-Identifier: LGPL-2.1-or-later

libc_wrapper_sources = files(
        'bpf.c',
        'fcntl.c',
        'ioprio.c',
        'kcmp.c',
        'kexec.c',
        'keyctl.c',
        'mempolicy.c',
        'mount.c',
        'pidfd.c',
        'quota.c',
        'sched.c',
        'signal.c',
        'stat.c',
        'unistd.c',
        'xattr.c',
)

subdir('musl')

sources += libc_wrapper_sources

libc_wrapper_static = static_library(
        'c-wrapper',
        libc_wrapper_sources,
        include_directories : system_includes,
        implicit_include_directories : false,
        dependencies : [userspace],
        # The shims deliberately redeclare libc syscall wrappers as weak references so call sites can do
        # runtime fallback. Suppress the redundant-decl warning, and the -Waddress warning that strict
        # builds fire on `if (foo)` against a weak symbol redeclared after glibc's strong declaration.
        c_args : ['-fvisibility=default', '-Wno-redundant-decls', '-Wno-address'],
        build_by_default : false)
