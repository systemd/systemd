# SPDX-License-Identifier: LGPL-2.1-or-later

basic_sources = files(
        'MurmurHash2.c',
        'af-list.c',
        'alloc-util.c',
        'ansi-color.c',
        'architecture.c',
        'argv-util.c',
        'arphrd-util.c',
        'assert-util.c',
        'audit-util.c',
        'btrfs.c',
        'build.c',
        'build-path.c',
        'bus-label.c',
        'cap-list.c',
        'capability-util.c',
        'capsule-util.c',
        'cgroup-util.c',
        'chase.c',
        'chattr-util.c',
        'compress.c',
        'conf-files.c',
        'confidential-virt.c',
        'devnum-util.c',
        'dirent-util.c',
        'dlfcn-util.c',
        'efivars.c',
        'env-file.c',
        'env-util.c',
        'errno-list.c',
        'errno-util.c',
        'escape.c',
        'ether-addr-util.c',
        'extract-word.c',
        'fd-util.c',
        'fileio.c',
        'filesystems.c',
        'format-ifname.c',
        'format-util.c',
        'fs-util.c',
        'gcrypt-util.c',
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
        'iovec-util.c',
        'iovec-wrapper.c',
        'keyring-util.c',
        'label.c',
        'limits-util.c',
        'locale-util.c',
        'lock-util.c',
        'log.c',
        'log-context.c',
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
        'path-util.c',
        'percent-util.c',
        'pidfd-util.c',
        'pidref.c',
        'prioq.c',
        'proc-cmdline.c',
        'process-util.c',
        'procfs-util.c',
        'psi-util.c',
        'random-util.c',
        'ratelimit.c',
        'raw-clone.c',
        'recurse-dir.c',
        'replace-var.c',
        'rlimit-util.c',
        'runtime-scope.c',
        'sha256.c',
        'sigbus.c',
        'signal-util.c',
        'siphash24.c',
        'socket-util.c',
        'sort-util.c',
        'stat-util.c',
        'static-destruct.c',
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
        'unit-name.c',
        'user-util.c',
        'utf8.c',
        'virt.c',
        'xattr-util.c',
)

sources += basic_sources

generated_gperf_headers = []
foreach item : [
        # name,    source,         struct name,  prefix,    headers
        ['af',     af_sources,     'af',         '',        ['<sys/socket.h>'],       ],
        ['arphrd', arphrd_sources, 'arphrd',     'ARPHRD_', ['<linux/if_arp.h>'],     ],
        ['cap',    cap_sources,    'capability', '',        ['<linux/capability.h>'], ],
        ['errno',  [],             'errno',      '',        ['<errno.h>'],            ],
]

        fname = '@0@-list.txt'.format(item[0])
        generate_list = files('generate-@0@-list.sh'.format(item[0]))
        list_txt = custom_target(
                input : [generate_list, item[1]],
                output : fname,
                command : [env, 'bash', generate_list, cpp, system_include_args],
                capture : true)

        fname = '@0@-from-name.gperf'.format(item[0])
        gperf_file = custom_target(
                input : list_txt,
                output : fname,
                command : [generate_gperfs, item[2], item[3], '@INPUT@'] + item[4],
                capture : true)

        fname = '@0@-from-name.inc'.format(item[0])
        target1 = custom_target(
                input : gperf_file,
                output : fname,
                command : [gperf,
                           '-L', 'ANSI-C', '-t', '--ignore-case',
                           '-N', 'lookup_@0@'.format(item[2]),
                           '-H', 'hash_@0@_name'.format(item[2]),
                           '-p', '-C',
                           '@INPUT@'],
                capture : true)

        fname = '@0@-to-name.inc'.format(item[0])
        awkscript = '@0@-to-name.awk'.format(item[0])
        target2 = custom_target(
                input : [awkscript, list_txt],
                output : fname,
                command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
                capture : true)

        generated_gperf_headers += [target1, target2]
endforeach

generated_sources += generated_gperf_headers
basic_sources += generated_gperf_headers

############################################################

check_filesystems = find_program('check-filesystems.sh')
r = run_command(
        [
                'env', '--chdir', meson.project_build_root(),
                check_filesystems, cpp, files('filesystems-gperf.gperf'),
                system_include_args,
        ],
        check: false,
)
if r.returncode() != 0
        warning('Unknown filesystems defined in kernel headers:\n\n' + r.stdout())
endif

filesystems_gperf_h = custom_target(
        input : 'filesystems-gperf.gperf',
        output : 'filesystems-gperf.h',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

generate_filesystem_list = find_program('generate-filesystem-list.py')
fname = 'filesystem-list.inc'
filesystem_list_inc = custom_target(
        input : 'filesystems-gperf.gperf',
        output : fname,
        command : [generate_filesystem_list,
                   '@INPUT@'],
        capture : true)

generate_filesystem_switch_case_inc = find_program('generate-filesystem-switch-case.py')
fname = 'filesystem-switch-case.inc'
filesystem_switch_case_inc = custom_target(
        input : 'filesystems-gperf.gperf',
        output : fname,
        command : [generate_filesystem_switch_case_inc,
                   '@INPUT@'],
        capture : true)

generate_bpf_delegate_configs = find_program('generate-bpf-delegate-configs.py')
bpf_delegate_configs_inc = custom_target(
        input : files('include/linux/bpf.h'),
        output : 'bpf-delegate-configs.inc',
        command : [generate_bpf_delegate_configs,
                   'code',
                   '@INPUT@'],
        capture : true)

generated_sources += [filesystem_list_inc, filesystem_switch_case_inc, filesystems_gperf_h, bpf_delegate_configs_inc]
basic_sources += [filesystem_list_inc, filesystem_switch_case_inc, filesystems_gperf_h, bpf_delegate_configs_inc]

libbasic_static = static_library(
        'basic',
        basic_sources,
        fundamental_sources,
        include_directories : basic_includes,
        implicit_include_directories : false,
        dependencies : [libcap,
                        libdl,
                        libgcrypt_cflags,
                        liblz4_cflags,
                        libm,
                        librt,
                        libxz_cflags,
                        libzstd_cflags,
                        threads,
                        userspace],
        c_args : ['-fvisibility=default'],
        build_by_default : false)
