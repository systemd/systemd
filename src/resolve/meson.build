# SPDX-License-Identifier: LGPL-2.1-or-later

resolve_includes = [includes, include_directories('.')]

basic_dns_sources = files(
        'resolved-dns-dnssec.c',
        'resolved-dns-dnssec.h',
        'resolved-dns-packet.c',
        'resolved-dns-packet.h',
        'resolved-dns-rr.c',
        'resolved-dns-rr.h',
        'resolved-dns-answer.c',
        'resolved-dns-answer.h',
        'resolved-dns-question.c',
        'resolved-dns-question.h',
        'resolved-util.c',
        'resolved-util.h',
        'dns-type.c',
        'dns-type.h',
)

systemd_resolved_sources = files(
        'resolved-bus.c',
        'resolved-bus.h',
        'resolved-conf.c',
        'resolved-conf.h',
        'resolved-def.h',
        'resolved-dns-cache.c',
        'resolved-dns-cache.h',
        'resolved-dns-query.c',
        'resolved-dns-query.h',
        'resolved-dns-scope.c',
        'resolved-dns-scope.h',
        'resolved-dns-search-domain.c',
        'resolved-dns-search-domain.h',
        'resolved-dns-server.c',
        'resolved-dns-server.h',
        'resolved-dns-stream.c',
        'resolved-dns-stream.h',
        'resolved-dns-stub.c',
        'resolved-dns-stub.h',
        'resolved-dns-synthesize.c',
        'resolved-dns-synthesize.h',
        'resolved-dns-transaction.c',
        'resolved-dns-transaction.h',
        'resolved-dns-trust-anchor.c',
        'resolved-dns-trust-anchor.h',
        'resolved-dns-zone.c',
        'resolved-dns-zone.h',
        'resolved-dnssd-bus.c',
        'resolved-dnssd-bus.h',
        'resolved-dnssd.c',
        'resolved-dnssd.h',
        'resolved-dnstls.h',
        'resolved-etc-hosts.c',
        'resolved-etc-hosts.h',
        'resolved-link-bus.c',
        'resolved-link-bus.h',
        'resolved-link.c',
        'resolved-link.h',
        'resolved-llmnr.c',
        'resolved-llmnr.h',
        'resolved-manager.c',
        'resolved-manager.h',
        'resolved-mdns.c',
        'resolved-mdns.h',
        'resolved-resolv-conf.c',
        'resolved-resolv-conf.h',
        'resolved-socket-graveyard.c',
        'resolved-socket-graveyard.h',
        'resolved-varlink.c',
        'resolved-varlink.h',
)

resolvectl_sources = files(
         'resolvconf-compat.c',
         'resolvconf-compat.h',
         'resolvectl.c',
         'resolvectl.h',
)

############################################################

dns_type_list_txt = custom_target(
        'dns_type-list.txt',
        input : ['generate-dns_type-list.sed', 'dns-type.h'],
        output : 'dns_type-list.txt',
        command : [sed, '-n', '-r', '-f', '@INPUT0@', '@INPUT1@'],
        capture : true)

generate_dns_type_gperf = find_program('generate-dns_type-gperf.py')

gperf_file = custom_target(
        'dns_type-from-name.gperf',
        input : dns_type_list_txt,
        output : 'dns_type-from-name.gperf',
        command : [generate_dns_type_gperf, 'dns_type', 'DNS_TYPE_', '@INPUT@'],
        capture : true)

basic_dns_sources += custom_target(
        'dns_type-from-name.h',
        input : gperf_file,
        output : 'dns_type-from-name.h',
        command : [gperf,
                   '-L', 'ANSI-C', '-t', '--ignore-case',
                   '-N', 'lookup_dns_type',
                   '-H', 'hash_dns_type_name',
                   '-p', '-C',
                   '@INPUT@'],
        capture : true)

basic_dns_sources += custom_target(
        'dns_type-to-name.h',
        input : ['dns_type-to-name.awk', dns_type_list_txt],
        output : 'dns_type-to-name.h',
        command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
        capture : true)

libsystemd_resolve_core = static_library(
        'systemd-resolve-core',
        basic_dns_sources,
        include_directories : includes,
        build_by_default : false)

systemd_resolved_sources += custom_target(
        'resolved_gperf.c',
        input : 'resolved-gperf.gperf',
        output : 'resolved-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_resolved_sources += custom_target(
        'resolved_dnssd_gperf.c',
        input : 'resolved-dnssd-gperf.gperf',
        output : 'resolved-dnssd-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_resolved_dependencies = [threads, libm] + [lib_openssl_or_gcrypt]
if conf.get('ENABLE_DNS_OVER_TLS') == 1
        if conf.get('DNS_OVER_TLS_USE_GNUTLS') == 1
                systemd_resolved_sources += files(
                        'resolved-dnstls-gnutls.c',
                        'resolved-dnstls-gnutls.h',
                )
                systemd_resolved_dependencies += libgnutls
        elif conf.get('DNS_OVER_TLS_USE_OPENSSL') == 1
                systemd_resolved_sources += files(
                        'resolved-dnstls-openssl.c',
                        'resolved-dnstls-openssl.h',
                )
                systemd_resolved_dependencies += libopenssl
        else
                error('unknown dependency for supporting DNS-over-TLS')
        endif
endif

if conf.get('ENABLE_RESOLVE') == 1
        install_data('org.freedesktop.resolve1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.resolve1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.resolve1.policy',
                     install_dir : polkitpolicydir)
        install_data('resolv.conf',
                     install_dir : rootlibexecdir)
endif

custom_target(
        'resolved.conf',
        input : 'resolved.conf.in',
        output : 'resolved.conf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : conf.get('ENABLE_RESOLVE') == 1 and install_sysconfdir_samples,
        install_dir : pkgsysconfdir)

############################################################

tests += [
        [files('test-resolve-tables.c'),
         [libsystemd_resolve_core,
          libshared],
         [lib_openssl_or_gcrypt,
          libm]],

        [files('test-dns-packet.c'),
         [libsystemd_resolve_core,
          libshared],
         [lib_openssl_or_gcrypt,
          libm]],

        [files('test-resolved-etc-hosts.c',
               'resolved-etc-hosts.c',
               'resolved-etc-hosts.h'),
         [libsystemd_resolve_core,
          libshared],
         [lib_openssl_or_gcrypt,
          libm]],

        [files('test-resolved-packet.c'),
         [libsystemd_resolve_core,
          libshared],
         [lib_openssl_or_gcrypt,
          libm]],

        [files('test-resolved-stream.c')
         + basic_dns_sources + systemd_resolved_sources,
         [libshared],
         [lib_openssl_or_gcrypt,
          libm]
         + systemd_resolved_dependencies,
         resolve_includes],

        [files('test-dnssec.c'),
         [libsystemd_resolve_core,
          libshared],
         [lib_openssl_or_gcrypt,
          libm],
         [], 'HAVE_OPENSSL_OR_GCRYPT'],

        [files('test-dnssec-complex.c'),
         [libsystemd_resolve_core,
          libshared],
         [lib_openssl_or_gcrypt,
          libm],
         [], '', 'manual'],
]

fuzzers += [
        [files('fuzz-dns-packet.c'),
         [libsystemd_resolve_core,
          libshared],
         [lib_openssl_or_gcrypt,
          libm]],
        [files('fuzz-etc-hosts.c',
          'resolved-etc-hosts.c',
          'resolved-etc-hosts.h'),
         [libsystemd_resolve_core,
          libshared],
         [lib_openssl_or_gcrypt,
          libm]],
]

systemd_resolved_sources += files('resolved.c')
