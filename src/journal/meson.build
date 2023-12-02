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

if get_option('link-journalctl-shared')
        journalctl_link_with = [libshared]
else
        journalctl_link_with = [
                libbasic_gcrypt,
                libshared_static,
                libsystemd_static,
        ]
endif

journal_test_template = test_template + {
        'link_with' : [
                libjournal_core,
                libshared,
        ],
}

journal_fuzz_template = fuzz_template + {
        'link_with' : [
                libjournal_core,
                libshared,
        ],
        'dependencies' : libselinux,
}

executables += [
        libexec_template + {
                'name' : 'systemd-journald',
                'sources' : files('journald.c'),
                'link_with' : [
                        libjournal_core,
                        libshared,
                ],
                'dependencies' : [
                        liblz4,
                        libselinux,
                        libxz,
                        libzstd,
                        threads,
                ],
        },
        libexec_template + {
                'name' : 'systemd-bsod',
                'public' : true,
                'conditions' : ['HAVE_QRENCODE'],
                'sources' : files('bsod.c'),
                'link_with' : libshared,
                'dependencies' : libqrencode,
        },
        executable_template + {
                'name' : 'systemd-cat',
                'public' : true,
                'sources' : files('cat.c'),
                'link_with' : [
                        libjournal_core,
                        libshared,
                ],
                'dependencies' : threads,
        },
        executable_template + {
                'name' : 'journalctl',
                'public' : true,
                'sources' : files('journalctl.c'),
                'link_with' : journalctl_link_with,
                'dependencies' : [
                        libdl,
                        liblz4,
                        libxz,
                        libzstd,
                        threads,
                ],
        },
        journal_test_template + {
                'sources' : files('test-journald-config.c'),
                'dependencies' : [
                        liblz4,
                        libselinux,
                        libxz,
                ],
        },
        journal_test_template + {
                'sources' : files('test-journald-syslog.c'),
                'dependencies' : [
                        liblz4,
                        libselinux,
                        libxz,
                        threads,
                ],
        },
        journal_test_template + {
                'sources' : files('test-journald-tables.c'),
                'dependencies' : [
                        libselinux,
                ],
        },
        journal_fuzz_template + {
                'sources' : files(
                        'fuzz-journald-audit.c',
                        'fuzz-journald.c',
                ),
        },
        journal_fuzz_template + {
                'sources' : files(
                        'fuzz-journald-kmsg.c',
                        'fuzz-journald.c',
                ),
        },
        journal_fuzz_template + {
                'sources' : files(
                        'fuzz-journald-native.c',
                        'fuzz-journald.c',
                ),
        },
        journal_fuzz_template + {
                'sources' : files(
                        'fuzz-journald-native-fd.c',
                        'fuzz-journald.c',
                ),
        },
        journal_fuzz_template + {
                'sources' : files(
                        'fuzz-journald-stream.c',
                        'fuzz-journald.c',
                ),
        },
        journal_fuzz_template + {
                'sources' : files(
                        'fuzz-journald-syslog.c',
                        'fuzz-journald.c',
                ),
        },
]

if install_sysconfdir_samples
        install_data('journald.conf',
                     install_dir : pkgconfigfiledir)
endif

if get_option('create-log-dirs')
        install_emptydir('/var/log/journal',
                         install_mode : 'rwxr-xr-x')
        if get_option('adm-group')
                meson.add_install_script(
                        sh, '-c',
                        'setfacl -nm g:adm:rx,d:g:adm:rx $DESTDIR/var/log/journal || :')
        endif
        if get_option('wheel-group')
                meson.add_install_script(
                        sh, '-c',
                        'setfacl -nm g:wheel:rx,d:g:wheel:rx $DESTDIR/var/log/journal || :')
        endif
endif
