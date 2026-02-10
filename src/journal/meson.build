# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_journald_sources = files(
        'journald.c',
)
systemd_journald_extract_sources = files(
        'journald-audit.c',
        'journald-client.c',
        'journald-config.c',
        'journald-console.c',
        'journald-context.c',
        'journald-kmsg.c',
        'journald-manager.c',
        'journald-native.c',
        'journald-rate-limit.c',
        'journald-socket.c',
        'journald-stream.c',
        'journald-sync.c',
        'journald-syslog.c',
        'journald-varlink.c',
        'journald-wall.c',
        # Build fuzz-journald.c as part of systemd-journald so we only compile it once instead of once per
        # fuzz test.
        'fuzz-journald-util.c',
)

journald_gperf_c = custom_target(
        input : 'journald-gperf.gperf',
        output : 'journald-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

generated_sources += journald_gperf_c
systemd_journald_extract_sources += journald_gperf_c

journalctl_sources = files(
        'journalctl.c',
        'journalctl-authenticate.c',
        'journalctl-catalog.c',
        'journalctl-filter.c',
        'journalctl-misc.c',
        'journalctl-show.c',
        'journalctl-util.c',
        'journalctl-varlink.c',
        'journalctl-varlink-server.c',
)

if get_option('link-journalctl-shared')
        journalctl_link_with = [libshared]
else
        journalctl_link_with = [
                libshared_static,
                libsystemd_static,
        ]
endif

journal_test_template = test_template + {
        'objects' : ['systemd-journald'],
}

journal_fuzz_template = fuzz_template + {
        'objects' : ['systemd-journald'],
        'dependencies' : libselinux_cflags,
}

executables += [
        libexec_template + {
                'name' : 'systemd-journald',
                'sources' : systemd_journald_sources,
                'extract' : systemd_journald_extract_sources,
                'dependencies' : [
                        liblz4_cflags,
                        libselinux_cflags,
                        libxz_cflags,
                        libzstd_cflags,
                        threads,
                ],
        },
        libexec_template + {
                'name' : 'systemd-bsod',
                'public' : true,
                'conditions' : ['HAVE_QRENCODE'],
                'sources' : files('bsod.c'),
                'dependencies' : libqrencode,
        },
        executable_template + {
                'name' : 'systemd-cat',
                'public' : true,
                'sources' : files('cat.c'),
                'objects' : ['systemd-journald'],
                'dependencies' : [threads],
        },
        executable_template + {
                'name' : 'journalctl',
                'public' : true,
                'sources' : journalctl_sources,
                'link_with' : journalctl_link_with,
                'dependencies' : [
                        libdl,
                        liblz4_cflags,
                        libxz_cflags,
                        libzstd_cflags,
                        threads,
                ],
        },
        journal_test_template + {
                'sources' : files('test-journald-config.c'),
                'dependencies' : [
                        liblz4_cflags,
                        libselinux_cflags,
                        libxz_cflags,
                ],
        },
        journal_test_template + {
                'sources' : files('test-journald-rate-limit.c'),
                'dependencies' : [
                        liblz4_cflags,
                        libselinux_cflags,
                        libxz_cflags,
                ],
        },
        journal_test_template + {
                'sources' : files('test-journald-syslog.c'),
                'dependencies' : [
                        liblz4_cflags,
                        libselinux_cflags,
                        libxz_cflags,
                        threads,
                ],
        },
        journal_test_template + {
                'sources' : files('test-journald-tables.c'),
                'dependencies' : [
                        libselinux_cflags,
                ],
        },
        journal_fuzz_template + {
                'sources' : files('fuzz-journald-audit.c'),
        },
        journal_fuzz_template + {
                'sources' : files('fuzz-journald-kmsg.c'),
        },
        journal_fuzz_template + {
                'sources' : files('fuzz-journald-native.c'),
        },
        journal_fuzz_template + {
                'sources' : files('fuzz-journald-native-fd.c'),
        },
        journal_fuzz_template + {
                'sources' : files('fuzz-journald-stream.c'),
        },
        journal_fuzz_template + {
                'sources' : files('fuzz-journald-syslog.c'),
        },
]

custom_target(
        input : 'journald.conf.in',
        output: 'journald.conf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : install_sysconfdir_samples,
        install_dir : pkgconfigfiledir)

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
