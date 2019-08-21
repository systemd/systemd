# SPDX-License-Identifier: LGPL-2.1+

fuzzers += [
        [['src/fuzz/fuzz-bus-message.c'],
         [libshared],
         []],

        [['src/fuzz/fuzz-catalog.c'],
         [libjournal_core,
          libshared],
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

        [['src/fuzz/fuzz-varlink.c'],
         [libshared],
         []],

        [['src/fuzz/fuzz-unit-file.c'],
         [libcore,
          libshared],
         [libmount]],

        [['src/fuzz/fuzz-journald-audit.c',
          'src/fuzz/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/fuzz/fuzz-journald-kmsg.c',
          'src/fuzz/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/fuzz/fuzz-journald-native.c',
          'src/fuzz/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/fuzz/fuzz-journald-native-fd.c',
          'src/fuzz/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/fuzz/fuzz-journald-stream.c',
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

        [['src/fuzz/fuzz-udev-database.c'],
         [libshared],
         []],

        [['src/fuzz/fuzz-udev-rules.c'],
         [libudev_core,
          libudev_static,
          libsystemd_network,
          libshared],
         [threads,
          libacl]],

        [['src/fuzz/fuzz-compress.c'],
         [libshared],
         []],

        [['src/fuzz/fuzz-bus-label.c'],
         [libshared],
         []],

        [['src/fuzz/fuzz-env-file.c'],
         [libshared],
         []],

        [['src/fuzz/fuzz-hostname-util.c'],
         [libshared],
         []],

        [['src/fuzz/fuzz-nspawn-settings.c'],
         [libshared,
          libnspawn_core],
         [libseccomp]],

        [['src/fuzz/fuzz-nspawn-oci.c'],
         [libshared,
          libnspawn_core],
         [libseccomp]],

        [['src/fuzz/fuzz-calendarspec.c'],
         [libshared],
         []],

        [['src/fuzz/fuzz-time-util.c'],
         [libshared],
         []],

        [['src/fuzz/fuzz-fido-id-desc.c',
          'src/udev/fido_id/fido_id_desc.c'],
         [],
         []]
]
