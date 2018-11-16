# SPDX-License-Identifier: LGPL-2.1+

fuzzers += [
        [['src/fuzz/fuzz-bus-message.c'],
         [libshared],
         []],

        [['src/fuzz/fuzz-dns-packet.c',
          dns_type_headers],
         [libsystemd_resolve_core,
          libshared],
         [libgcrypt,
          libgpg_error,
          libm]],

        [['src/fuzz/fuzz-dhcp6-client.c',
          'src/libsystemd-network/dhcp-identifier.h',
          'src/libsystemd-network/dhcp-identifier.c',
          'src/libsystemd-network/dhcp6-internal.h',
          'src/systemd/sd-dhcp6-client.h'],
         [libshared,
          libsystemd_network],
         []],

        [['src/fuzz/fuzz-dhcp-server.c'],
         [libsystemd_network,
          libshared],
         []],

        [['src/fuzz/fuzz-lldp.c'],
         [libshared,
          libsystemd_network],
         []],

        [['src/fuzz/fuzz-ndisc-rs.c',
          'src/libsystemd-network/dhcp-identifier.h',
          'src/libsystemd-network/dhcp-identifier.c',
          'src/libsystemd-network/icmp6-util.h',
          'src/systemd/sd-dhcp6-client.h',
          'src/systemd/sd-ndisc.h'],
         [libshared,
          libsystemd_network],
         []],

        [['src/fuzz/fuzz-json.c'],
         [libshared],
         []],

        [['src/fuzz/fuzz-unit-file.c'],
         [libcore,
          libshared],
         [libmount]],

        [['src/fuzz/fuzz-journald-kmsg.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/fuzz/fuzz-journald-native.c',
          'src/fuzz/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/fuzz/fuzz-journald-syslog.c',
          'src/fuzz/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/fuzz/fuzz-journal-remote.c'],
         [libsystemd_journal_remote,
          libshared],
         []],

        [['src/fuzz/fuzz-compress.c'],
         [libshared],
         []],
]
