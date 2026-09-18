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
                        'report-basic.c',
                        'report-basic-server.c',
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
                'name' : 'systemd-report-geoip',
                'sources' : files(
                        'report-geoip.c',
                        'report-geoip-server.c',
                ),
                'dependencies' : [
                        libcurl_cflags,
                ],
                'conditions' : ['HAVE_LIBCURL'],
        },
        libexec_template + {
                'name' : 'systemd-report-hwmon',
                'sources' : files(
                        'report-hwmon.c',
                        'report-hwmon-server.c',
                ),
        },
        libexec_template + {
                'name' : 'systemd-report-sign-plain',
                'sources' : files(
                        'report-sign-plain.c',
                ),
                'dependencies' : libopenssl_cflags,
                'conditions' : ['HAVE_OPENSSL'],
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
                        'HAVE_OPENSSL',
                        'HAVE_TPM2',
                ],
        },
        libexec_template + {
                'name' : 'systemd-report-sign-tsm',
                'sources' : files(
                        'report-sign-tsm.c',
                ),
        },
]

custom_target(
        input : 'report-geoip.conf.in',
        output : 'report-geoip.conf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : conf.get('HAVE_LIBCURL') == 1 and install_sysconfdir_samples,
        install_dir : pkgconfigfiledir)
