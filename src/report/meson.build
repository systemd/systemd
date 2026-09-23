# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-report',
                'public' : true,
                'export' : files(
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
                'public' : true,
                'export' : files(
                        'report-basic.c',
                        'report-basic-server.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-report-cgroup',
                'sources' : files('report-cgroup-server.c'),
                'export' : files('report-cgroup.c'),
        },
        libexec_template + {
                'name' : 'systemd-report-files',
                'export' : files(
                        'report-files.c',
                        'report-files-server.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-report-hwmon',
                'export' : files(
                        'report-hwmon.c',
                        'report-hwmon-server.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-report-sign-plain',
                'export' : files(
                        'report-sign-plain.c',
                ),
                'dependencies' : libopenssl_cflags,
                'conditions' : ['HAVE_OPENSSL'],
        },
        libexec_template + {
                'name' : 'systemd-report-sign-tpm2',
                'export': files(
                        'report-sign-tpm2.c',
                ),
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
                'export' : files(
                        'report-sign-tsm.c',
                ),
        },
        test_template + {
                'sources' : files('test-report-cgroup.c'),
                'import' : ['systemd-report-cgroup'],
                # test_pressure_large_scrape() sends a lot of replies, which is slow under sanitizers
                'timeout' : 120,
        },
]
