# SPDX-License-Identifier: LGPL-2.1-or-later

sources = files(
        'journald-audit.c',
        'journald-client.c',
        'journald-console.c',
        'journald-context.c',
        'journald-kmsg.c',
        'journald-native.c',
        'journald-rate-limit.c',
        'journald-server.c',
        'journald-stream.c',
        'journald-syslog.c',
        'journald-wall.c',
        'managed-journal-file.c',
)

sources += custom_target(
        'journald-gperf.c',
        input : 'journald-gperf.gperf',
        output : 'journald-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

libjournal_core = static_library(
        'journal-core',
        sources,
        include_directories : includes,
        dependencies: [threads,
                       userspace],
        build_by_default : false)

journal_includes = [includes, include_directories('.')]

if get_option('link-journalctl-shared')
        journalctl_link_with = [libshared]
else
        journalctl_link_with = [libsystemd_static,
                                libshared_static,
                                libbasic_gcrypt]
endif

executables += [
        [
                {
                        'name' : 'systemd-journald',
                },
                daemon_template + {
                        'sources' : files('journald.c'),
                        'link_with' : [libjournal_core,
                                       libshared],
                        'dependencies' : [liblz4,
                                          libselinux,
                                          libxz,
                                          libzstd,
                                          threads,
                                          userspace,
                                          versiondep],
                },
        ],
        [
                {
                        'name' : 'systemd-cat',
                        'public' : true,
                },
                executable_template + {
                        'sources' : files('cat.c'),
                        'link_with' : [libjournal_core,
                                       libshared],
                        'dependencies' : [threads,
                                          userspace,
                                          versiondep],
                },
        ],
        [
                {
                        'name' : 'journalctl',
                        'public' : true,
                },
                executable_template + {
                        'sources' : files('journalctl.c'),
                        'link_with' : journalctl_link_with,
                        'dependencies' : [libdl,
                                          liblz4,
                                          libxz,
                                          libzstd,
                                          threads,
                                          userspace,
                                          versiondep],
                        'install_dir' : rootbindir,
                },
        ],
]

if install_sysconfdir_samples
        install_data('journald.conf',
                     install_dir : pkgsysconfdir)
endif

if get_option('create-log-dirs')
        meson.add_install_script(
                'sh', '-c',
                mkdir_p.format('/var/log/journal'))
        meson.add_install_script(
                'sh', '-c',
                '''chown 0:0 $DESTDIR/var/log/journal &&
                   chmod 755 $DESTDIR/var/log/journal || :''')
        if get_option('adm-group')
                meson.add_install_script(
                        'sh', '-c',
                        'setfacl -nm g:adm:rx,d:g:adm:rx $DESTDIR/var/log/journal || :')
        endif
        if get_option('wheel-group')
                meson.add_install_script(
                        'sh', '-c',
                        'setfacl -nm g:wheel:rx,d:g:wheel:rx $DESTDIR/var/log/journal || :')
        endif
endif

############################################################

test_journal_base = {
        'link_with' : [libjournal_core, libshared],
}

tests += [
        {
                'sources' : files('test-journal-config.c'),
                'dependencies' : [
                        liblz4,
                        libselinux,
                        libxz,
                ],
                'base' : test_journal_base,
        },
        {
                'sources' : files('test-journal-flush.c'),
                'base' : test_journal_base,
        },
        {
                'sources' : files('test-journal-interleaving.c'),
                'base' : test_journal_base,
        },
        {
                'sources' : files('test-journal-stream.c'),
                'base' : test_journal_base,
        },
        {
                'sources' : files('test-journal-syslog.c'),
                'dependencies' : [
                        liblz4,
                        libselinux,
                        libxz,
                        threads,
                ],
                'base' : test_journal_base,
        },
        {
                'sources' : files('test-journal-verify.c'),
                'base' : test_journal_base,
                'timeout' : 90,
        },
        {
                'sources' : files('test-journal.c'),
                'base' : test_journal_base,
        },
]

fuzzer_journald_base = {
        'link_with' : [libjournal_core, libshared],
        'dependencies' : [libselinux],
}

fuzzers += [
        {
                'sources' : files(
                        'fuzz-journald-audit.c',
                        'fuzz-journald.c',
                ),
                'base' : fuzzer_journald_base,
        },
        {
                'sources' : files(
                        'fuzz-journald-kmsg.c',
                        'fuzz-journald.c',
                ),
                'base' : fuzzer_journald_base,
        },
        {
                'sources' : files(
                        'fuzz-journald-native.c',
                        'fuzz-journald.c',
                ),
                'base' : fuzzer_journald_base,
        },
        {
                'sources' : files(
                        'fuzz-journald-native-fd.c',
                        'fuzz-journald.c',
                ),
                'base' : fuzzer_journald_base,
        },
        {
                'sources' : files(
                        'fuzz-journald-stream.c',
                        'fuzz-journald.c',
                ),
                'base' : fuzzer_journald_base,
        },
        {
                'sources' : files(
                        'fuzz-journald-syslog.c',
                        'fuzz-journald.c',
                ),
                'base' : fuzzer_journald_base,
        },
]
