# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_journald_sources = files(
        'journald.c',
)
systemd_journald_extract_sources = files(
        'audit-type.c',
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
)

journald_gperf_c = custom_target(
        input : 'journald-gperf.gperf',
        output : 'journald-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

generated_sources += journald_gperf_c
systemd_journald_extract_sources += journald_gperf_c

generate_audit_type_list = files('generate-audit_type-list.sh')
generate_audit_type_command = [env, 'bash', generate_audit_type_list, cpp]
if libaudit.found()
        generate_audit_type_command += [
                '-include', 'libaudit.h',
                '-I' + libaudit.get_variable('includedir'),
        ]
endif
generate_audit_type_command += system_include_args

audit_type_list_txt = custom_target(
        input : [generate_audit_type_list],
        output : 'audit_type-list.txt',
        command : generate_audit_type_command,
        capture : true)

audit_type_to_name = custom_target(
        input : ['audit_type-to-name.awk', audit_type_list_txt],
        output : 'audit_type-to-name.inc',
        command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
        capture : true)

generated_sources += audit_type_to_name
systemd_journald_extract_sources += audit_type_to_name

journalctl_sources = files(
        'journalctl.c',
        'journalctl-authenticate.c',
        'journalctl-catalog.c',
        'journalctl-filter.c',
        'journalctl-metrics.c',
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
        'objects' : [
                'fuzz-journald-audit',
                'systemd-journald',
        ],
        'dependencies' : libselinux_cflags,
}

executables += [
        libexec_template + {
                'name' : 'systemd-journald',
                'sources' : systemd_journald_sources,
                'extract' : systemd_journald_extract_sources,
                'dependencies' : [
                        libacl_cflags,
                        libaudit_cflags,
                        liblz4_cflags,
                        libpcre2_cflags,
                        libselinux_cflags,
                        libxz_cflags,
                        libzstd_cflags,
                ],
        },
        libexec_template + {
                'name' : 'systemd-bsod',
                'public' : true,
                'conditions' : ['HAVE_QRENCODE'],
                'sources' : files('bsod.c'),
                'dependencies' : [
                        libqrencode_cflags,
                ],
        },
        executable_template + {
                'name' : 'systemd-cat',
                'public' : true,
                'sources' : files('cat.c'),
                'objects' : ['systemd-journald'],
        },
        executable_template + {
                'name' : 'journalctl',
                'public' : true,
                'sources' : journalctl_sources,
                'link_with' : journalctl_link_with,
                'dependencies' : [
                        liblz4_cflags,
                        libopenssl_cflags,
                        libpcre2_cflags,
                        libxz_cflags,
                        libzstd_cflags,
                ],
        },
        journal_test_template + {
                'sources' : files('test-audit-type.c'),
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
                ],
        },
        journal_test_template + {
                'sources' : files('test-journald-tables.c'),
                'dependencies' : [
                        libselinux_cflags,
                ],
        },
        fuzz_template + {
                'sources' : files('fuzz-journald-audit.c'),
                # fuzz-journald-util.c is shared with the other fuzzers below.
                'extract' : files('fuzz-journald-util.c'),
                'objects' : ['systemd-journald'],
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
