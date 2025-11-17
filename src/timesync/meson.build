# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_TIMESYNCD') != 1
        subdir_done()
endif

timesyncd_sources = files(
        'timesyncd.c',
        'timesyncd-bus.c',
)
timesyncd_extract_sources = files(
        'timesyncd-conf.c',
        'timesyncd-manager.c',
        'timesyncd-server.c',
)

nts_sources = files(
        'nts_crypto_openssl.c',
        'nts_packet.c',
        'nts_error.c',
        'nts_extfields.c',
        'nts_tls.c',
)

timesyncd_gperf_c = custom_target(
        input : 'timesyncd-gperf.gperf',
        output : 'timesyncd-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

generated_sources += timesyncd_gperf_c
timesyncd_extract_sources += timesyncd_gperf_c

if get_option('link-timesyncd-shared')
        timesyncd_link_with = [libshared]
else
        timesyncd_link_with = [libsystemd_static,
                               libshared_static]
endif

# Add OpenSSL to the list of dependencies if NTS is enabled
if conf.get('ENABLE_TIMESYNC_NTS') == 1
        crypto_deps = [libopenssl]
        timesyncd_extract_sources += nts_sources
else
        crypto_deps = []
endif

executables += [
        libexec_template + {
                'name' : 'systemd-timesyncd',
                'sources' : timesyncd_sources,
                'extract' : timesyncd_extract_sources,
                'include_directories' : [libexec_template['include_directories'], include_directories('.')],
                'c_args' : c_args,
                'link_with' : timesyncd_link_with,
                'dependencies' : [
                        libm,
                        threads,
                        crypto_deps,
                ],
        },
        libexec_template + {
                'name' : 'systemd-time-wait-sync',
                'sources' : files('wait-sync.c'),
                'objects' : ['systemd-timesyncd'],
                'link_with' : timesyncd_link_with,
                'dependencies' : [libm, crypto_deps],
        },
        test_template + {
                'sources' : files('test-timesync.c'),
                'objects' : ['systemd-timesyncd'],
                'c_args' : c_args,
                'link_with' : timesyncd_link_with,
                'dependencies' : [libm, crypto_deps],
        },
]

if conf.get('ENABLE_TIMESYNC_NTS') == 1
        executables += [
                test_template + {
                        'sources' : files('test-nts.c') + nts_sources,
                        'link_with' : timesyncd_link_with,
                        'dependencies' : crypto_deps,
                },
                fuzz_template + {
                        'sources' : files('fuzz-nts.c', 'fuzz-nullcipher.c', 'nts_packet.c'),
                        'link_with' : libshared,
                        'dependencies' : crypto_deps,
                },
                fuzz_template + {
                        'sources' : files('fuzz-nts-extfields.c', 'fuzz-nullcipher.c', 'nts_extfields.c'),
                        'link_with' : libshared,
                        'dependencies' : crypto_deps,
                },
        ]
endif

custom_target(
        input : 'timesyncd.conf.in',
        output : 'timesyncd.conf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : conf.get('ENABLE_TIMESYNCD') == 1 and install_sysconfdir_samples,
        install_dir : pkgconfigfiledir)

install_data(
        'org.freedesktop.timesync1.conf',
        install_dir : dbuspolicydir)
install_data(
        'org.freedesktop.timesync1.service',
        install_dir : dbussystemservicedir)
install_data(
        '80-systemd-timesync.list',
        install_dir : ntpservicelistdir)
install_data(
        'org.freedesktop.timesync1.policy',
        install_dir : polkitpolicydir)
