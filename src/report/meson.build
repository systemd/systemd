# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-report',
                'public' : true,
                'sources' : files('report.c'),
        },
        libexec_template + {
                'name' : 'systemd-report-cgroup-metrics',
                'sources' : files(
                        'report-cgroup-metrics.c',
                        'report-cgroup-metrics-server.c',
                ),
        },
]
