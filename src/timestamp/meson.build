# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_TIMESTAMPD') != 1
        subdir_done()
endif

timestampd_gperf_c = custom_target(
        input : 'timestampd-gperf.gperf',
        output : 'timestampd-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

generated_sources += timestampd_gperf_c

systemd_timestampd_sources = files(
        'timestampd.c',
        'timestampd-request.c',
        'timestampd-request-tcp.c',
)

# The HTTP transport is only available when curl is.
if conf.get('HAVE_LIBCURL') == 1
        systemd_timestampd_sources += files('timestampd-request-http.c')
endif

executables += [
        libexec_template + {
                'name' : 'systemd-timestampd',
                'sources' : systemd_timestampd_sources + [timestampd_gperf_c],
                'export' : files('timestampd-tsp.c'),
                'dependencies' : [
                        libcurl_cflags,
                        libopenssl_cflags,
                ],
        },
        test_template + {
                'sources' : files('test-timestampd.c'),
                'import' : ['systemd-timestampd'],
                'dependencies' : [
                        libopenssl_cflags,
                ],
        },
]

install_data(
        'timestampd.conf',
        install_dir : pkgconfigfiledir,
        install_tag : 'runtime')
