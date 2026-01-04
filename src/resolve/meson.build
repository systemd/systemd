# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_RESOLVE') != 1
        subdir_done()
endif

systemd_resolved_sources = files(
        'resolved.c',
)
systemd_resolved_extract_sources = files(
        'resolved-bus.c',
        'resolved-conf.c',
        'resolved-dns-browse-services.c',
        'resolved-dns-cache.c',
        'resolved-dns-delegate.c',
        'resolved-dns-delegate-bus.c',
        'resolved-dns-dnssec.c',
        'resolved-dns-query.c',
        'resolved-dns-scope.c',
        'resolved-dns-search-domain.c',
        'resolved-dns-server.c',
        'resolved-dns-stream.c',
        'resolved-dns-stub.c',
        'resolved-dns-synthesize.c',
        'resolved-dns-transaction.c',
        'resolved-dns-trust-anchor.c',
        'resolved-dns-zone.c',
        'resolved-dnssd-bus.c',
        'resolved-dnssd.c',
        'resolved-etc-hosts.c',
        'resolved-hook.c',
        'resolved-link-bus.c',
        'resolved-link.c',
        'resolved-llmnr.c',
        'resolved-manager.c',
        'resolved-mdns.c',
        'resolved-resolv-conf.c',
        'resolved-socket-graveyard.c',
        'resolved-util.c',
        'resolved-varlink.c',
)

############################################################

resolved_gperf_c = custom_target(
        input : 'resolved-gperf.gperf',
        output : 'resolved-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

resolved_dnssd_gperf_c = custom_target(
        input : 'resolved-dnssd-gperf.gperf',
        output : 'resolved-dnssd-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

resolved_dns_delegate_gperf_c = custom_target(
        input : 'resolved-dns-delegate-gperf.gperf',
        output : 'resolved-dns-delegate-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

generated_sources += [resolved_gperf_c, resolved_dnssd_gperf_c, resolved_dns_delegate_gperf_c]
systemd_resolved_extract_sources += [resolved_gperf_c, resolved_dnssd_gperf_c, resolved_dns_delegate_gperf_c]

if conf.get('ENABLE_DNS_OVER_TLS') == 1
        systemd_resolved_extract_sources += files(
                'resolved-dnstls.c',
        )
endif

resolve_common_template = {
        'dependencies' : [
                libidn2_cflags,
                libopenssl,
                libm,
                threads,
        ],
}

resolve_test_template = test_template + resolve_common_template + {'objects' : ['systemd-resolved']}
resolve_fuzz_template = fuzz_template + resolve_common_template + {'objects' : ['systemd-resolved']}

executables += [
        libexec_template + resolve_common_template + {
                'name' : 'systemd-resolved',
                'dbus' : true,
                'sources' : systemd_resolved_sources,
                'extract' : systemd_resolved_extract_sources,
        },
        executable_template + resolve_common_template + {
                'name' : 'resolvectl',
                'public' : true,
                'sources' : files(
                        'resolvconf-compat.c',
                        'resolvectl.c',
                ),
                'objects' : ['systemd-resolved'],
        },
        resolve_test_template + {
                'sources' : files('test-resolve-tables.c'),
        },
        resolve_test_template + {
                'sources' : files('test-dns-answer.c'),
        },
        resolve_test_template + {
                'sources' : files('test-dns-cache.c'),
        },
        resolve_test_template + {
                'sources' : files('test-dns-packet.c'),
        },
        resolve_test_template + {
                'sources' : files('test-dns-packet-append.c'),
        },
        resolve_test_template + {
                'sources' : files('test-dns-packet-extract.c'),
        },
        resolve_test_template + {
                'sources' : files('test-dns-rr.c'),
        },
        resolve_test_template + {
                'sources' : files('test-dns-question.c'),
        },
        resolve_test_template + {
                'sources' : files('test-resolved-etc-hosts.c'),
        },
        resolve_test_template + {
                'sources' : files('test-resolved-packet.c'),
        },
        resolve_test_template + {
                'sources' : files('test-dnssec.c'),
                'conditions' : ['HAVE_OPENSSL'],
        },
        resolve_test_template + {
                'sources' : files('test-dnssec-complex.c'),
                'type' : 'manual',
        },
        resolve_test_template + {
                'sources' : files('test-dns-search-domain.c'),
        },
        resolve_test_template + {
                'sources' : files('test-dns-synthesize.c'),
        },
        resolve_test_template + {
                'sources' : files('test-dns-zone.c'),
        },
        resolve_test_template + {
                'sources' : files('test-resolved-link.c'),
        },
        resolve_test_template + {
                'sources' : files('test-dns-query.c'),
        },
        resolve_test_template + {
                'sources' : files('test-resolved-stream.c'),
        },
        resolve_test_template + {
                'sources' : files('test-resolved-dummy-server.c'),
                'type' : 'manual',
        },
        resolve_fuzz_template + {
                'sources' : files('fuzz-dns-packet.c'),
        },
        resolve_fuzz_template + {
                'sources' : files('fuzz-etc-hosts.c'),
        },
        resolve_fuzz_template + {
                'sources' : files('fuzz-resource-record.c'),
        },
]

install_data('org.freedesktop.resolve1.conf',
             install_dir : dbuspolicydir)
install_data('org.freedesktop.resolve1.service',
             install_dir : dbussystemservicedir)
install_data('org.freedesktop.resolve1.policy',
             install_dir : polkitpolicydir)
install_data('resolv.conf',
                install_dir : libexecdir)

install_symlink('resolvconf',
                pointing_to : sbin_to_bin + 'resolvectl',
                install_dir : sbindir)

# symlink for backwards compatibility after rename
install_symlink('systemd-resolve',
                pointing_to : 'resolvectl',
                install_dir : bindir)

custom_target(
        input : 'resolved.conf.in',
        output : 'resolved.conf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : install_sysconfdir_samples,
        install_dir : pkgconfigfiledir)
