# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-report',
                'public' : true,
                'sources' : files(
                        'report.c',
                        'report-upload.c',
                ),
                'link_with' : [libcurlutil_static, libshared],
                'dependencies' : [libcurl],
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
]
