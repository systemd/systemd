# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_REPORT') != 1
        subdir_done()
endif

executables += [
        executable_template + {
                'name' : 'systemd-report-example',
                'sources' : files(
                        'report-example.c',
                        'report-server.c',
                ),
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
                        'report-server.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-report-cgroup',
                'sources' : files(
                        'report-cgroup.c',
                        'report-server.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-report-diskspace',
                'sources' : files(
                        'report-diskspace.c',
                        'report-server.c',
                ),
                'dependencies' : libmount_cflags,
                'conditions' : ['HAVE_LIBMOUNT'],
        },
        libexec_template + {
                'name' : 'systemd-report-files',
                'sources' : files(
                        'report-files.c',
                        'report-server.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-report-hwmon',
                'sources' : files(
                        'report-hwmon.c',
                        'report-server.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-report-netstat',
                'sources' : files(
                        'report-netstat.c',
                        'report-server.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-report-sign-plain',
                'sources' : files(
                        'report-server.c',
                        'report-sign-plain.c',
                ),
                'dependencies' : libopenssl_cflags,
                'conditions' : ['HAVE_OPENSSL'],
        },
        libexec_template + {
                'name' : 'systemd-report-sign-tpm2',
                'sources': files(
                        'report-server.c',
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
                'sources' : files(
                        'report-server.c',
                        'report-sign-tsm.c',
                ),
        },
]
