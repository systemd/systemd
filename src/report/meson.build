# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-report',
                'public' : true,
                'sources' : files(
                        'report.c',
                        'report-upload.c',
                ),
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
                'name' : 'systemd-report-pid1',
                'sources' : files(
                        'report-pid1.c',
                        'report-pid1-server.c',
                ),
        },
]
