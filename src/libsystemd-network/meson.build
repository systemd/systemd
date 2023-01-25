# SPDX-License-Identifier: LGPL-2.1-or-later

sources = files(
        'arp-util.c',
        'dhcp-identifier.c',
        'dhcp-network.c',
        'dhcp-option.c',
        'dhcp-packet.c',
        'dhcp6-network.c',
        'dhcp6-option.c',
        'dhcp6-protocol.c',
        'icmp6-util.c',
        'lldp-neighbor.c',
        'lldp-network.c',
        'ndisc-router.c',
        'network-common.c',
        'network-internal.c',
        'sd-dhcp-client.c',
        'sd-dhcp-lease.c',
        'sd-dhcp-server.c',
        'sd-dhcp6-client.c',
        'sd-dhcp6-lease.c',
        'sd-ipv4acd.c',
        'sd-ipv4ll.c',
        'sd-lldp-rx.c',
        'sd-lldp-tx.c',
        'sd-ndisc.c',
        'sd-radv.c',
)

libsystemd_network = static_library(
        'systemd-network',
        sources,
        include_directories : includes,
        build_by_default : false)

libsystemd_network_includes = [includes, include_directories('.')]

############################################################

tests += [
        { 'sources' : files('test-dhcp-option.c'),
          'link_with' : [libshared, libsystemd_network] },

        { 'sources' : files('test-sd-dhcp-lease.c'),
          'link_with' : [libshared, libsystemd_network] },

        { 'sources' : files('test-dhcp-client.c'),
          'link_with' : [libshared, libsystemd_network] },

        { 'sources' : files('test-dhcp-server.c'),
          'link_with' : [libshared, libsystemd_network] },

        { 'sources' : files('test-ipv4ll.c'),
          'link_with' : [libshared, libsystemd_network] },

        { 'sources' : files('test-ipv4ll-manual.c'),
          'link_with' : [libshared, libsystemd_network],
          'type' : 'manual' },

        { 'sources' : files('test-acd.c'),
          'link_with' : [libshared, libsystemd_network],
          'type' : 'manual' },

        { 'sources' : files('test-ndisc-rs.c'),
          'link_with' : [libshared, libsystemd_network] },

        { 'sources' : files('test-ndisc-ra.c'),
          'link_with' : [libshared, libsystemd_network] },

        { 'sources' : files('test-dhcp6-client.c'),
          'link_with' : [libshared, libsystemd_network] },

        { 'sources' : files('test-lldp-rx.c'),
          'link_with' : [libshared, libsystemd_network] },
]

fuzzers += [
        [files('fuzz-dhcp-client.c'),
         [libshared,
          libsystemd_network]],

        [files('fuzz-dhcp6-client.c'),
         [libshared,
          libsystemd_network]],

        [files('fuzz-dhcp-server.c'),
         [libsystemd_network,
          libshared]],

        [files('fuzz-dhcp-server-relay.c'),
         [libsystemd_network,
          libshared]],

        [files('fuzz-lldp-rx.c'),
         [libshared,
          libsystemd_network]],

        [files('fuzz-ndisc-rs.c'),
         [libshared,
          libsystemd_network]],
]
