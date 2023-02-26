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
        dependencies : userspace,
        build_by_default : false)

libsystemd_network_includes = [includes, include_directories('.')]

############################################################

test_libsystemd_network_base = {
        'link_with' : [libshared, libsystemd_network],
}

tests += [
        {
                'sources' : files('test-acd.c'),
                'base' : test_libsystemd_network_base,
                'type' : 'manual',
        },
        {
                'sources' : files('test-dhcp-client.c'),
                'base' : test_libsystemd_network_base,
        },
        {
                'sources' : files('test-dhcp-option.c'),
                'base' : test_libsystemd_network_base,
        },
        {
                'sources' : files('test-dhcp-server.c'),
                'base' : test_libsystemd_network_base,
        },
        {
                'sources' : files('test-dhcp6-client.c'),
                'base' : test_libsystemd_network_base,
        },
        {
                'sources' : files('test-ipv4ll-manual.c'),
                'base' : test_libsystemd_network_base,
                'type' : 'manual',
        },
        {
                'sources' : files('test-ipv4ll.c'),
                'base' : test_libsystemd_network_base,
        },
        {
                'sources' : files('test-lldp-rx.c'),
                'base' : test_libsystemd_network_base,
        },
        {
                'sources' : files('test-ndisc-ra.c'),
                'base' : test_libsystemd_network_base,
        },
        {
                'sources' : files('test-ndisc-rs.c'),
                'base' : test_libsystemd_network_base,
        },
        {
                'sources' : files('test-sd-dhcp-lease.c'),
                'base' : test_libsystemd_network_base,
        },
]

fuzzer_network_base = {
        'link_with' : [libshared, libsystemd_network],
}

fuzzers += [
        {
                'sources' : files('fuzz-dhcp-client.c'),
                'base' : fuzzer_network_base,
        },
        {
                'sources' : files('fuzz-dhcp6-client.c'),
                'base' : fuzzer_network_base,
        },
        {
                'sources' : files('fuzz-dhcp-server.c'),
                'base' : fuzzer_network_base,
        },
        {
                'sources' : files('fuzz-dhcp-server-relay.c'),
                'base' : fuzzer_network_base,
        },
        {
                'sources' : files('fuzz-lldp-rx.c'),
                'base' : fuzzer_network_base,
        },
        {
                'sources' : files('fuzz-ndisc-rs.c'),
                'base' : fuzzer_network_base,
        },
]
