# SPDX-License-Identifier: LGPL-2.1-or-later

report_executables = [
        {
                'name' : 'systemd-report',
                'public' : true,
                'export' : files(
                        'report.c',
                        'report-generate.c',
                        'report-sign.c',
                        'report-upload.c',
                ),
        },
        {
                'name' : 'systemd-report-basic',
                'public' : true,
                'export' : files(
                        'report-basic.c',
                        'report-basic-server.c',
                ),
        },
        {
                'name' : 'systemd-report-cgroup',
                'export' : files(
                        'report-cgroup.c',
                        'report-cgroup-server.c',
                ),
        },
        {
                'name' : 'systemd-report-files',
                'export' : files(
                        'report-files.c',
                        'report-files-server.c',
                ),
        },
        {
                'name' : 'systemd-report-sign-plain',
                'export' : files(
                        'report-sign-plain.c',
                ),
                'dependencies' : libopenssl_cflags,
                'conditions' : ['HAVE_OPENSSL'],
        },
        {
                'name' : 'systemd-report-sign-tsm',
                'export' : files(
                        'report-sign-tsm.c',
                ),
        },
]

foreach exe : report_executables
        exe2 = {
                'name' : exe['name'] + '.standalone',
                'import' : [exe['name']],
                'link_with' : [
                        libc_wrapper_static,
                        libbasic_static,
                        libshared_static,
                        libsystemd_static,
                ]
        }
        foreach optional : ['public', 'dependencies', 'conditions']
                if optional in exe
                        exe2 += { optional : exe[optional] }
                endif
        endforeach

        executables += [
                libexec_template + exe,
                libexec_template + exe2,
        ]
endforeach
