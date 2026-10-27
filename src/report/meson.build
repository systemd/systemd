# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_REPORT') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-report',
                'sources' : files(
                        'report.c',
                        'report-generate.c',
                        'report-sign.c',
                        'report-upload.c',
                ),
                'dependencies' : [
                        libcurl_cflags,
                ],
        },
        libexec_template + {
                'name' : 'systemd-report-basic',
                'sources' : files('report-basic.c'),
                'export' : files('report-server.c'),
        },
        # Compile and link the provider example to keep the documented contract checked;
        # runtime behavior is covered by integration tests of the actual providers.
        executable_template + {
                'name' : 'systemd-report-example',
                'sources' : files('report-example.c'),
                'import' : ['systemd-report-basic'],
                'build_by_default' : want_tests != 'false',
                'install' : 'no',
        },
        libexec_template + {
                'name' : 'systemd-report-cgroup',
                'sources' : files('report-cgroup.c'),
                'export' : files('report-cgroup-pressure.c'),
                'import' : ['systemd-report-basic'],
        },
        libexec_template + {
                'name' : 'systemd-report-diskhealth',
                'sources' : files(
                        'report-diskhealth.c',
                        'report-diskhealth-ata.c',
                        'report-diskhealth-nvme.c',
                ),
                'import' : ['systemd-report-basic'],
        },
        libexec_template + {
                'name' : 'systemd-report-diskspace',
                'sources' : files('report-diskspace.c'),
                'import' : ['systemd-report-basic'],
                'dependencies' : libmount_cflags,
                'conditions' : ['HAVE_LIBMOUNT'],
        },
        libexec_template + {
                'name' : 'systemd-report-files',
                'sources' : files('report-files.c'),
                'import' : ['systemd-report-basic'],
        },
        libexec_template + {
                'name' : 'systemd-report-geoip',
                'sources' : files('report-geoip.c'),
                'import' : ['systemd-report-basic'],
                'dependencies' : [
                        libcurl_cflags,
                ],
                'conditions' : ['HAVE_LIBCURL'],
        },
        libexec_template + {
                'name' : 'systemd-report-hwmon',
                'sources' : files('report-hwmon.c'),
                'import' : ['systemd-report-basic'],
        },
        libexec_template + {
                'name' : 'systemd-report-netstat',
                'sources' : files('report-netstat.c'),
                'import' : ['systemd-report-basic'],
        },
        libexec_template + {
                'name' : 'systemd-report-sign-plain',
                'sources' : files('report-sign-plain.c'),
                'import' : ['systemd-report-basic'],
                'dependencies' : libopenssl_cflags,
                'conditions' : ['HAVE_OPENSSL'],
        },
        libexec_template + {
                'name' : 'systemd-report-sign-tpm2',
                'sources' : files('report-sign-tpm2.c'),
                'import' : ['systemd-report-basic'],
                'dependencies' : [
                        libopenssl_cflags,
                        tpm2_cflags,
                ],
                'conditions' : [
                        'HAVE_OPENSSL',
                        'HAVE_TPM2',
                ],
        },
        libexec_template + {
                'name' : 'systemd-report-sign-tsm',
                'sources' : files('report-sign-tsm.c'),
                'import' : ['systemd-report-basic'],
        },
        test_template + {
                'sources' : files('test-report-cgroup.c'),
                'import' : ['systemd-report-cgroup'],
                # test_pressure_large_scrape() sends a lot of replies, which is slow under sanitizers
                'timeout' : 120,
        },
]

custom_target(
        input : 'report-geoip.conf.in',
        output : 'report-geoip.conf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : conf.get('HAVE_LIBCURL') == 1 and install_sysconfdir_samples,
        install_dir : pkgconfigfiledir)
