# SPDX-License-Identifier: LGPL-2.1+

basic_dns_sources = files('''
        resolved-dns-dnssec.c
        resolved-dns-dnssec.h
        resolved-dns-packet.c
        resolved-dns-packet.h
        resolved-dns-rr.c
        resolved-dns-rr.h
        resolved-dns-answer.c
        resolved-dns-answer.h
        resolved-dns-question.c
        resolved-dns-question.h
        dns-type.c
'''.split())

dns_type_h = files('dns-type.h')[0]

systemd_resolved_sources = files('''
        resolved.c
        resolved-manager.c
        resolved-manager.h
        resolved-dnssd.c
        resolved-dnssd.h
        resolved-dnssd-bus.c
        resolved-dnssd-bus.h
        resolved-conf.c
        resolved-conf.h
        resolved-resolv-conf.c
        resolved-resolv-conf.h
        resolved-bus.c
        resolved-bus.h
        resolved-link.h
        resolved-link.c
        resolved-link-bus.c
        resolved-link-bus.h
        resolved-llmnr.h
        resolved-llmnr.c
        resolved-mdns.h
        resolved-mdns.c
        resolved-def.h
        resolved-dns-query.h
        resolved-dns-query.c
        resolved-dns-synthesize.h
        resolved-dns-synthesize.c
        resolved-dns-transaction.h
        resolved-dns-transaction.c
        resolved-dns-scope.h
        resolved-dns-scope.c
        resolved-dns-server.h
        resolved-dns-server.c
        resolved-dns-search-domain.h
        resolved-dns-search-domain.c
        resolved-dns-cache.h
        resolved-dns-cache.c
        resolved-dns-zone.h
        resolved-dns-zone.c
        resolved-dns-stream.h
        resolved-dns-stream.c
        resolved-dns-trust-anchor.h
        resolved-dns-trust-anchor.c
        resolved-dns-stub.h
        resolved-dns-stub.c
        resolved-etc-hosts.h
        resolved-etc-hosts.c
        resolved-dnstls.h
'''.split())

resolvectl_sources = files('''
         resolvconf-compat.c
         resolvconf-compat.h
         resolvectl.c
         resolvectl.h
'''.split())

############################################################

dns_type_list_txt = custom_target(
        'dns_type-list.txt',
        input : ['generate-dns_type-list.sed', dns_type_h],
        output : 'dns_type-list.txt',
        command : [sed, '-n', '-r', '-f', '@INPUT0@', '@INPUT1@'],
        capture : true)

generate_dns_type_gperf = find_program('generate-dns_type-gperf.py')

dns_type_headers = [dns_type_h]
foreach item : [['dns_type', dns_type_list_txt, 'dns_type', 'DNS_TYPE_']]

        fname = '@0@-from-name.gperf'.format(item[0])
        gperf_file = custom_target(
                fname,
                input : item[1],
                output : fname,
                command : [generate_dns_type_gperf, item[2], item[3], '@INPUT@'],
                capture : true)

        fname = '@0@-from-name.h'.format(item[0])
        target1 = custom_target(
                fname,
                input : gperf_file,
                output : fname,
                command : [gperf,
                           '-L', 'ANSI-C', '-t', '--ignore-case',
                           '-N', 'lookup_@0@'.format(item[2]),
                           '-H', 'hash_@0@_name'.format(item[2]),
                           '-p', '-C',
                           '@INPUT@'],
                capture : true)

        fname = '@0@-to-name.h'.format(item[0])
        awkscript = '@0@-to-name.awk'.format(item[0])
        target2 = custom_target(
                fname,
                input : [awkscript, item[1]],
                output : fname,
                command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
                capture : true)

        dns_type_headers += [target1, target2]
endforeach

resolved_gperf_c = custom_target(
        'resolved_gperf.c',
        input : 'resolved-gperf.gperf',
        output : 'resolved-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

resolved_dnssd_gperf_c = custom_target(
        'resolved_dnssd_gperf.c',
        input : 'resolved-dnssd-gperf.gperf',
        output : 'resolved-dnssd-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

libsystemd_resolve_core = static_library(
        'systemd-resolve-core',
        basic_dns_sources,
        dns_type_headers,
        include_directories : includes)

systemd_resolved_sources += [resolved_gperf_c, resolved_dnssd_gperf_c]

systemd_resolved_dependencies = [threads, libgpg_error, libm, libidn]
if conf.get('ENABLE_DNS_OVER_TLS') == 1
        systemd_resolved_sources += [files(['resolved-dnstls-gnutls.c', 'resolved-dnstls-gnutls.h'])]
        systemd_resolved_dependencies += [libgnutls]
endif

if conf.get('ENABLE_RESOLVE') == 1
        install_data('org.freedesktop.resolve1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.resolve1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.resolve1.policy',
                     install_dir : polkitpolicydir)

        resolved_conf = configure_file(
                input : 'resolved.conf.in',
                output : 'resolved.conf',
                configuration : substs)
        install_data(resolved_conf,
                     install_dir : pkgsysconfdir)

        install_data('resolv.conf',
                     install_dir : rootlibexecdir)
endif

tests += [
        [['src/resolve/test-resolve-tables.c',
          dns_type_headers,
          'src/shared/test-tables.h'],
         [libsystemd_resolve_core,
          libshared],
         [libgcrypt,
          libgpg_error,
          libm],
         'ENABLE_RESOLVE'],

        [['src/resolve/test-dns-packet.c',
          dns_type_headers],
         [libsystemd_resolve_core,
          libshared],
         [libgcrypt,
          libgpg_error,
          libm],
         'ENABLE_RESOLVE'],

        [['src/resolve/test-resolved-packet.c',
          dns_type_headers],
         [libsystemd_resolve_core,
          libshared],
         [libgcrypt,
          libgpg_error,
          libm],
         'ENABLE_RESOLVE'],

        [['src/resolve/test-dnssec.c',
          dns_type_headers],
         [libsystemd_resolve_core,
          libshared],
         [libgcrypt,
          libgpg_error,
          libm],
         'ENABLE_RESOLVE'],

        [['src/resolve/test-dnssec-complex.c',
          'src/resolve/dns-type.c',
          dns_type_headers],
         [],
         [],
         'ENABLE_RESOLVE', 'manual'],
]
