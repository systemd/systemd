# SPDX-License-Identifier: LGPL-2.1-or-later

basic_sources = files(
        'MurmurHash2.c',
        'af-list.c',
        'alloc-util.c',
        'architecture.c',
        'argv-util.c',
        'arphrd-util.c',
        'audit-util.c',
        'btrfs.c',
        'build.c',
        'bus-label.c',
        'cap-list.c',
        'capability-util.c',
        'cgroup-util.c',
        'chase.c',
        'chattr-util.c',
        'conf-files.c',
        'confidential-virt.c',
        'devnum-util.c',
        'dirent-util.c',
        'efivars.c',
        'env-file.c',
        'env-util.c',
        'errno-list.c',
        'escape.c',
        'ether-addr-util.c',
        'extract-word.c',
        'fd-util.c',
        'fileio.c',
        'filesystems.c',
        'format-util.c',
        'fs-util.c',
        'glob-util.c',
        'glyph-util.c',
        'gunicode.c',
        'hash-funcs.c',
        'hashmap.c',
        'hexdecoct.c',
        'hmac.c',
        'hostname-util.c',
        'in-addr-util.c',
        'initrd-util.c',
        'inotify-util.c',
        'io-util.c',
        'ioprio-util.c',
        'iovec-util.c',
        'iovec-wrapper.c',
        'label.c',
        'limits-util.c',
        'locale-util.c',
        'lock-util.c',
        'log.c',
        'login-util.c',
        'memfd-util.c',
        'memory-util.c',
        'mempool.c',
        'memstream-util.c',
        'mkdir.c',
        'mountpoint-util.c',
        'namespace-util.c',
        'nulstr-util.c',
        'ordered-set.c',
        'os-util.c',
        'parse-util.c',
        'path-lookup.c',
        'path-util.c',
        'percent-util.c',
        'pidref.c',
        'prioq.c',
        'proc-cmdline.c',
        'process-util.c',
        'procfs-util.c',
        'psi-util.c',
        'random-util.c',
        'ratelimit.c',
        'recurse-dir.c',
        'replace-var.c',
        'rlimit-util.c',
        'runtime-scope.c',
        'sigbus.c',
        'signal-util.c',
        'siphash24.c',
        'socket-util.c',
        'sort-util.c',
        'stat-util.c',
        'strbuf.c',
        'string-table.c',
        'string-util.c',
        'strv.c',
        'strxcpyx.c',
        'sync-util.c',
        'sysctl-util.c',
        'syslog-util.c',
        'terminal-util.c',
        'time-util.c',
        'tmpfile-util.c',
        'uid-classification.c',
        'uid-range.c',
        'unit-def.c',
        'unit-file.c',
        'unit-name.c',
        'user-util.c',
        'utf8.c',
        'virt.c',
        'xattr-util.c',
)

missing_audit_h = files('missing_audit.h')
missing_capability_h = files('missing_capability.h')
missing_socket_h = files('missing_socket.h')

missing_syscall_def_h = files('missing_syscall_def.h')
basic_sources += missing_syscall_def_h

generate_af_list = find_program('generate-af-list.sh')
af_list_txt = custom_target(
        'af-list.txt',
        output : 'af-list.txt',
        command : [generate_af_list, cpp, config_h, missing_socket_h],
        capture : true)

generate_arphrd_list = find_program('generate-arphrd-list.sh')
arphrd_list_txt = custom_target(
        'arphrd-list.txt',
        output : 'arphrd-list.txt',
        command : [generate_arphrd_list, cpp, config_h],
        capture : true)

generate_cap_list = find_program('generate-cap-list.sh')
cap_list_txt = custom_target(
        'cap-list.txt',
        output : 'cap-list.txt',
        command : [generate_cap_list, cpp, config_h, missing_capability_h],
        capture : true)

generate_errno_list = find_program('generate-errno-list.sh')
errno_list_txt = custom_target(
        'errno-list.txt',
        output : 'errno-list.txt',
        command : [generate_errno_list, cpp],
        capture : true)

generated_gperf_headers = []
foreach item : [['af',     af_list_txt,     'af',         ''],
                ['arphrd', arphrd_list_txt, 'arphrd',     'ARPHRD_'],
                ['cap',    cap_list_txt,    'capability', ''],
                ['errno',  errno_list_txt,  'errno',      '']]

        fname = '@0@-from-name.gperf'.format(item[0])
        gperf_file = custom_target(
                fname,
                input : item[1],
                output : fname,
                command : [generate_gperfs, item[2], item[3], '@INPUT@'],
                capture : true)

        fname = '@0@-from-name.h'.format(item[0])
        target1 = custom_target(
                fname,
                input : gperf_file,
                output : fname,
                command : [gperf,
                           '-L', 'ANSI-C', '-t', '--ignore-case',
                           '-N', 'lookup_@0@'.format(item[2]),
                           '-H', 'hash_@0@_name'.format(item[2]),
                           '-p', '-C',
                           '@INPUT@'],
                capture : true)

        fname = '@0@-to-name.h'.format(item[0])
        awkscript = '@0@-to-name.awk'.format(item[0])
        target2 = custom_target(
                fname,
                input : [awkscript, item[1]],
                output : fname,
                command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
                capture : true)

        generated_gperf_headers += [target1, target2]
endforeach

basic_sources += generated_gperf_headers

############################################################

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
        syscall_lists += files('syscalls-@0@.txt'.format(arch))
endforeach

missing_syscalls_py = find_program('missing_syscalls.py')

run_target(
        'update-syscall-header',
        command : [missing_syscalls_py,
                   missing_syscall_def_h,
                   syscall_lists])

############################################################

filesystem_includes = ['linux/magic.h',
                       'linux/gfs2_ondisk.h']

check_filesystems = find_program('check-filesystems.sh')
r = run_command([check_filesystems, cpp, files('filesystems-gperf.gperf')] + filesystem_includes, check: false)
if r.returncode() != 0
        error('Unknown filesystems defined in kernel headers:\n\n' + r.stdout())
endif

filesystems_gperf_h = custom_target(
        'filesystems-gperf.h',
        input : 'filesystems-gperf.gperf',
        output : 'filesystems-gperf.h',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

generate_filesystem_list = find_program('generate-filesystem-list.py')
fname = 'filesystem-list.h'
filesystem_list_h = custom_target(
        fname,
        input : 'filesystems-gperf.gperf',
        output : fname,
        command : [generate_filesystem_list,
                   '@INPUT@'],
        capture : true)

generate_filesystem_switch_case_h = find_program('generate-filesystem-switch-case.py')
fname = 'filesystem-switch-case.h'
filesystem_switch_case_h = custom_target(
        fname,
        input : 'filesystems-gperf.gperf',
        output : 'filesystem-switch-case.h',
        command : [generate_filesystem_switch_case_h,
                   '@INPUT@'],
        capture : true)

basic_sources += [filesystem_list_h, filesystem_switch_case_h, filesystems_gperf_h]

libbasic = static_library(
        'basic',
        basic_sources,
        fundamental_sources,
        include_directories : basic_includes,
        dependencies : [libcap,
                        libm,
                        librt,
                        threads,
                        userspace],
        c_args : ['-fvisibility=default'],
        build_by_default : false)

############################################################

basic_gcrypt_sources = files(
        'gcrypt-util.c',
)

# A convenience library that is separate from libbasic to avoid
# unnecessary linking to libgcrypt.
libbasic_gcrypt = static_library(
        'basic-gcrypt',
        basic_gcrypt_sources,
        include_directories : basic_includes,
        dependencies : [libgcrypt,
                        userspace],
        c_args : ['-fvisibility=default'],
        build_by_default : false)

############################################################

basic_compress_sources = files(
        'compress.c',
)

# A convenience library that is separate from libbasic to avoid unnecessary
# linking to the compression libraries.
libbasic_compress = static_library(
        'basic-compress',
        basic_compress_sources,
        include_directories : basic_includes,
        dependencies : [liblz4,
                        libxz,
                        libzstd,
                        userspace],
        c_args : ['-fvisibility=default'],
        build_by_default : false)
