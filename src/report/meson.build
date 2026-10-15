# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_REPORT') != 1
        subdir_done()
endif

executables += [
        # Compile and link the provider example to keep the documented contract checked;
        # runtime behavior is covered by integration tests of the actual providers.
        executable_template + {
                'name' : 'systemd-report-example',
                'sources' : files(
                        'report-example.c',
                ),
                # Compile the shared server once for all providers.
                'export' : files('report-server.c'),
                'build_by_default' : want_tests != 'false',
                'install' : 'no',
        },
        libexec_template + {
                'name' : 'systemd-report',
                'public' : true,
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
                'public' : true,
                'sources' : files(
                        'report-basic.c',
                ),
                'import' : ['systemd-report-example'],
        },
        libexec_template + {
                'name' : 'systemd-report-cgroup',
                'sources' : files(
                        'report-cgroup.c',
                ),
                'import' : ['systemd-report-example'],
        },
        libexec_template + {
                'name' : 'systemd-report-diskspace',
                'sources' : files(
                        'report-diskspace.c',
                ),
                'import' : ['systemd-report-example'],
                'dependencies' : libmount_cflags,
                'conditions' : ['HAVE_LIBMOUNT'],
        },
        libexec_template + {
                'name' : 'systemd-report-files',
                'sources' : files(
                        'report-files.c',
                ),
                'import' : ['systemd-report-example'],
        },
        libexec_template + {
                'name' : 'systemd-report-hwmon',
                'sources' : files(
                        'report-hwmon.c',
                ),
                'import' : ['systemd-report-example'],
        },
        libexec_template + {
                'name' : 'systemd-report-netstat',
                'sources' : files(
                        'report-netstat.c',
                ),
                'import' : ['systemd-report-example'],
        },
        libexec_template + {
                'name' : 'systemd-report-sign-plain',
                'sources' : files(
                        'report-sign-plain.c',
                ),
                'import' : ['systemd-report-example'],
                'dependencies' : libopenssl_cflags,
                'conditions' : ['HAVE_OPENSSL'],
        },
        libexec_template + {
                'name' : 'systemd-report-sign-tpm2',
                'sources': files(
                        'report-sign-tpm2.c',
                ),
                'import' : ['systemd-report-example'],
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
                'sources' : files(
                        'report-sign-tsm.c',
                ),
                'import' : ['systemd-report-example'],
        },
]
