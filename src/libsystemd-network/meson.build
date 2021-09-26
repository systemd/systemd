# SPDX-License-Identifier: LGPL-2.1-or-later

sources = files('''
        arp-util.c
        arp-util.h
        dhcp-client-internal.h
        dhcp-identifier.c
        dhcp-identifier.h
        dhcp-internal.h
        dhcp-lease-internal.h
        dhcp-network.c
        dhcp-option.c
        dhcp-packet.c
        dhcp-protocol.h
        dhcp-server-internal.h
        dhcp6-internal.h
        dhcp6-lease-internal.h
        dhcp6-network.c
        dhcp6-option.c
        dhcp6-protocol.h
        icmp6-util.c
        icmp6-util.h
        lldp-neighbor.c
        lldp-neighbor.h
        lldp-network.c
        lldp-network.h
        lldp-rx-internal.h
        ndisc-internal.h
        ndisc-router.c
        ndisc-router.h
        network-common.c
        network-common.h
        network-internal.c
        network-internal.h
        radv-internal.h
        sd-dhcp-client.c
        sd-dhcp-lease.c
        sd-dhcp-server.c
        sd-dhcp6-client.c
        sd-dhcp6-lease.c
        sd-ipv4acd.c
        sd-ipv4ll.c
        sd-lldp-rx.c
        sd-ndisc.c
        sd-radv.c
'''.split())

libsystemd_network = static_library(
        'systemd-network',
        sources,
        include_directories : includes)

libsystemd_network_includes = [includes, include_directories('.')]

############################################################

tests += [
        [['src/libsystemd-network/test-dhcp-option.c'],
         [libshared,
          libsystemd_network]],

        [['src/libsystemd-network/test-sd-dhcp-lease.c'],
         [libshared,
          libsystemd_network]],

        [['src/libsystemd-network/test-dhcp-client.c'],
         [libshared,
          libsystemd_network]],

        [['src/libsystemd-network/test-dhcp-server.c'],
         [libshared,
          libsystemd_network]],

        [['src/libsystemd-network/test-ipv4ll.c'],
         [libshared,
          libsystemd_network]],

        [['src/libsystemd-network/test-ipv4ll-manual.c'],
         [libshared,
          libsystemd_network],
         [], [], '', 'manual'],

        [['src/libsystemd-network/test-acd.c'],
         [libshared,
          libsystemd_network],
         [], [], '', 'manual'],

        [['src/libsystemd-network/test-ndisc-rs.c'],
         [libshared,
          libsystemd_network]],

        [['src/libsystemd-network/test-ndisc-ra.c'],
         [libshared,
          libsystemd_network]],

        [['src/libsystemd-network/test-dhcp6-client.c'],
         [libshared,
          libsystemd_network]],

        [['src/libsystemd-network/test-lldp.c'],
         [libshared,
          libsystemd_network]],
]

fuzzers += [
        [['src/libsystemd-network/fuzz-dhcp6-client.c'],
         [libshared,
          libsystemd_network]],

        [['src/libsystemd-network/fuzz-dhcp-server.c'],
         [libsystemd_network,
          libshared]],

        [['src/libsystemd-network/fuzz-lldp.c'],
         [libshared,
          libsystemd_network]],

        [['src/libsystemd-network/fuzz-ndisc-rs.c'],
         [libshared,
          libsystemd_network]],
]
