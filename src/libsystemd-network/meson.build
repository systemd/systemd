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

template = test_template + {
        'link_with' : [libshared, libsystemd_network],
        'suite' : 'network',
}

executables += [
        template + {
                'sources' : files('test-acd.c'),
                'type' : 'manual',
        },
        template + {
                'sources' : files('test-dhcp-client.c'),
        },
        template + {
                'sources' : files('test-dhcp-option.c'),
        },
        template + {
                'sources' : files('test-dhcp-server.c'),
        },
        template + {
                'sources' : files('test-dhcp6-client.c'),
        },
        template + {
                'sources' : files('test-ipv4ll-manual.c'),
                'type' : 'manual',
        },
        template + {
                'sources' : files('test-ipv4ll.c'),
        },
        template + {
                'sources' : files('test-lldp-rx.c'),
        },
        template + {
                'sources' : files('test-ndisc-ra.c'),
        },
        template + {
                'sources' : files('test-ndisc-rs.c'),
        },
        template + {
                'sources' : files('test-sd-dhcp-lease.c'),
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
