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
        # runtime fallback. Suppress -Wredundant-decls for that, and -Waddress because GCC intentionally
        # ignores the weak attribute when diagnosing `if (foo)` against a function symbol
        # (https://gcc.gnu.org/bugzilla/show_bug.cgi?id=33925).
        c_args : ['-fvisibility=default', '-Wno-redundant-decls', '-Wno-address'],
        build_by_default : false)
