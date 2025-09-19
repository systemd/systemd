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
        'tcp_connect.c',
        'nts_packet.c',
        'nts_extfields.c',
        'nts_error.c',
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

# Select the TLS dependency
if conf.get('NTS_USE_OPENSSL') == 1
        crypto_deps = [libopenssl]
        tls_c_args = ''
elif conf.get('NTS_USE_GNUTLS') == 1
        crypto_deps = [libgnutls]
        tls_c_args = '-DUSE_GNUTLS'
else
        crypto_deps = []
endif

# Select the cryptographic library; prefer Nettle if GnuTLS is used
opt = get_option('timesync-cryptolib')
if crypto_deps != []
        if opt == 'gcrypt' or (opt == 'auto' and conf.get('HAVE_GCRYPT') == 1)
                if conf.get('HAVE_GCRYPT') != 1
                        error('cryptolib(gcrypt) was selected but gcrypt is not available')
                endif
                nts_sources += files('nts_crypto_gcrypt.c')
                crypto_deps += [libgcrypt]
        elif opt == 'nettle' or (opt == 'auto' and conf.get('NTS_USE_GNUTLS') == 1)
                nts_sources += files('nts_crypto_nettle.c')
                libnettle = dependency('nettle',
                                       version : '>= 3.8',
                                       required : true)
                crypto_deps += [libnettle]
        elif opt == 'openssl' or (opt == 'auto' and conf.get('PREFER_OPENSSL') == 1)
                if libopenssl.version().version_compare('< 3.5')
                        error('OpenSSL @0@ does not work well for NTS; need at least OpenSSL 3.5, or use timesync-nts=gnutls and/or cryptolib=gcrypt.'.format(libopenssl.version()))
                endif
                nts_sources += files('nts_crypto_openssl.c')
                crypto_deps += [libopenssl]
        else
                error('No cryptographic solution for NTS available')
        endif

        timesyncd_extract_sources += nts_sources
else
        if opt != 'auto'
                error('Cannot set NTS crypto without having a TLS solution')
        endif
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
                'sources' : files('fuzz-nts.c', 'nts_packet.c'),
                'link_with' : libshared,
                'dependencies' : crypto_deps,
        },
        fuzz_template + {
                'sources' : files('fuzz-nts-extfields.c', 'nts_extfields.c'),
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
