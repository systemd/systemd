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
        'capability-list.c',
        'capability-util.c',
        'capsule-util.c',
        'cgroup-util.c',
        'chase.c',
        'chattr-util.c',
        'compress.c',
        'conf-files.c',
        'confidential-virt.c',
        'device-nodes.c',
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
        # name,             source,             prefix,    headers
        ['af',              af_sources,         '',        ['<sys/socket.h>'],       ],
        ['arphrd',          arphrd_sources,     'ARPHRD_', ['<linux/if_arp.h>'],     ],
        ['capability',      capability_sources, '',        ['<linux/capability.h>'], ],
        ['errno',           [],                 '',        ['<errno.h>'],            ],
        ['statx-mask',      statx_sources                                            ],
        ['statx-attribute', statx_sources                                            ],
]

        generate_list = files('generate-@0@-list.sh'.format(item[0]))
        list_txt = custom_target(
                input : [generate_list, item[1]],
                output : '@0@-list.txt'.format(item[0]),
                command : [env, 'bash', generate_list, cpp, system_include_args],
                capture : true)

        awkscript = '@0@-to-name.awk'.format(item[0])
        target = custom_target(
                input : [awkscript, list_txt],
                output : '@0@-to-name.inc'.format(item[0]),
                command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
                capture : true)

        generated_gperf_headers += [target]

        if item.length() > 2
                gperf_file = custom_target(
                        input : list_txt,
                        output : '@0@-from-name.gperf'.format(item[0]),
                        command : [generate_gperfs, item[0], item[2], '@INPUT@'] + item[3],
                        capture : true)

                target = custom_target(
                        input : gperf_file,
                        output : '@0@-from-name.inc'.format(item[0]),
                        command : [gperf,
                                '-L', 'ANSI-C', '-t', '--ignore-case',
                                '-N', 'lookup_@0@'.format(item[0]),
                                '-H', 'hash_@0@_name'.format(item[0]),
                                '-p', '-C',
                                '@INPUT@'],
                        capture : true)

                generated_gperf_headers += [target]
        endif
endforeach

generated_sources += generated_gperf_headers
basic_sources += generated_gperf_headers

############################################################

filesystem_sets_py = files('filesystem-sets.py')
filesystem_sets_c = custom_target(
        output : 'filesystem-sets.c',
        command : [filesystem_sets_py,
                   'fs-type-to-string',
                   'filesystem-sets',
                   'fs-in-group'],
        capture : true)

filesystems_gperf_gperf = custom_target(
        output : 'filesystems-gperf.gperf',
        command : [filesystem_sets_py,
                   'gperf'],
        capture : true)

filesystems_gperf_h = custom_target(
        input : filesystems_gperf_gperf,
        output : 'filesystems-gperf.h',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

generated_sources += [filesystem_sets_c, filesystems_gperf_gperf, filesystems_gperf_h]
basic_sources += [filesystem_sets_c, filesystems_gperf_h]

test('kernel-filesystem-magics',
     filesystem_sets_py,
     args : ['check'],
     env : ['CPP=@0@'.format(cpp)])

libbasic_static = static_library(
        'basic',
        basic_sources,
        fundamental_sources,
        include_directories : basic_includes,
        implicit_include_directories : false,
        dependencies : [libdl,
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
