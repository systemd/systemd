# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
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
                        'report-basic-server.c',
                        'report-basic.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-report-cgroup',
                'sources' : files(
                        'report-cgroup.c',
                        'report-cgroup-server.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-report-files',
                'sources' : files(
                        'report-files.c',
                        'report-files-server.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-report-sign-plain',
                'conditions' : [
                        'HAVE_OPENSSL',
                ],
                'sources' : files(
                        'report-sign-plain.c',
                ),
                'dependencies' : libopenssl_cflags,
        },
        libexec_template + {
                'name' : 'systemd-report-sign-tsm',
                'sources' : files(
                        'report-sign-tsm.c',
                ),
        },
]
