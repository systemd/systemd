# SPDX-License-Identifier: LGPL-2.1-or-later

libc_wrapper_sources = files(
        'bpf.c',
        'ioprio.c',
        'kcmp.c',
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

subdir('oss-fuzz')

sources += libc_wrapper_sources

libc_wrapper_static = static_library(
        'c-wrapper',
        libc_wrapper_sources,
        include_directories : system_includes,
        implicit_include_directories : false,
        dependencies : [userspace],
        c_args : ['-fvisibility=default'],
        build_by_default : false)
