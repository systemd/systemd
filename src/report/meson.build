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
                'export' : files(
                        'report-cgroup.c',
                        'report-cgroup-server.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-report-files',
                'export' : files(
                        'report-files.c',
                        'report-files-server.c',
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
                'name' : 'systemd-report-sign-tsm',
                'export' : files(
                        'report-sign-tsm.c',
                ),
        },
]
