# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-report',
                'public' : true,
                'sources' : files('report.c'),
        },

        libexec_template + {
                'name' : 'systemd-report-facts',
                'public' : true,
                'sources' : files(
                        'report-facts-server.c',
                        'report-facts.c',
                ),
        },
]
