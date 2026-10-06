# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-report',
                'sources' : files(
                        'report.c',
                        'report-generate.c',
                        'report-sign.c',
                        'report-upload.c',
                ),
                'conditions' : ['ENABLE_REPORT'],
                'dependencies' : [
                        libcurl_cflags,
                ],
                'public' : true,
        },
        libexec_template + {
                'name' : 'systemd-report-basic',
                'sources' : files(
                        'report-basic.c',
                        'report-basic-server.c',
                ),
                'conditions' : ['ENABLE_REPORT'],
                'public' : true,
        },
        libexec_template + {
                'name' : 'systemd-report-cgroup',
                'sources' : files(
                        'report-cgroup.c',
                        'report-cgroup-server.c',
                ),
                'conditions' : ['ENABLE_REPORT'],
        },
        libexec_template + {
                'name' : 'systemd-report-diskspace',
                'sources' : files(
                        'report-diskspace.c',
                        'report-diskspace-server.c',
                ),
                'dependencies' : libmount_cflags,
                'conditions' : [
                        'ENABLE_REPORT',
                        'HAVE_LIBMOUNT',
                ],
        },
        libexec_template + {
                'name' : 'systemd-report-files',
                'sources' : files(
                        'report-files.c',
                        'report-files-server.c',
                ),
                'conditions' : ['ENABLE_REPORT'],
        },
        libexec_template + {
                'name' : 'systemd-report-hwmon',
                'sources' : files(
                        'report-hwmon.c',
                        'report-hwmon-server.c',
                ),
                'conditions' : ['ENABLE_REPORT'],
        },
        libexec_template + {
                'name' : 'systemd-report-sign-plain',
                'sources' : files(
                        'report-sign-plain.c',
                ),
                'dependencies' : libopenssl_cflags,
                'conditions' : [
                        'ENABLE_REPORT',
                        'HAVE_OPENSSL',
                ],
        },
        libexec_template + {
                'name' : 'systemd-report-sign-tpm2',
                'sources': files(
                        'report-sign-tpm2.c',
                ),
                'dependencies' : [
                        libopenssl_cflags,
                        tpm2_cflags,
                ],
                'conditions' : [
                        'ENABLE_REPORT',
                        'HAVE_OPENSSL',
                        'HAVE_TPM2',
                ],
        },
        libexec_template + {
                'name' : 'systemd-report-sign-tsm',
                'sources' : files(
                        'report-sign-tsm.c',
                ),
                'conditions' : ['ENABLE_REPORT'],
        },
]
