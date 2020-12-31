# SPDX-License-Identifier: LGPL-2.1-or-later

fuzzers += [
        [['src/fuzz/fuzz-bus-message.c']],

        [['src/fuzz/fuzz-catalog.c'],
         [libjournal_core,
          libshared]],

        [['src/resolve/fuzz-dns-packet.c',
          dns_type_headers],
         [libsystemd_resolve_core,
          libshared],
         [libgcrypt,
          libgpg_error,
          libm]],

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

        [['src/fuzz/fuzz-json.c']],

        [['src/fuzz/fuzz-varlink.c']],

        [['src/core/fuzz-unit-file.c'],
         [libcore,
          libshared],
         [libmount]],

        [['src/journal/fuzz-journald-audit.c',
          'src/journal/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/journal/fuzz-journald-kmsg.c',
          'src/journal/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/journal/fuzz-journald-native.c',
          'src/journal/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/journal/fuzz-journald-native-fd.c',
          'src/journal/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/journal/fuzz-journald-stream.c',
          'src/journal/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/journal/fuzz-journald-syslog.c',
          'src/journal/fuzz-journald.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/journal-remote/fuzz-journal-remote.c'],
         [libsystemd_journal_remote,
          libshared]],

        [['src/fuzz/fuzz-udev-database.c']],

        [['src/udev/fuzz-udev-rules.c'],
         [libudevd_core,
          libshared],
         [threads,
          libacl]],

        [['src/fuzz/fuzz-compress.c']],

        [['src/fuzz/fuzz-bus-label.c']],

        [['src/fuzz/fuzz-env-file.c']],

        [['src/fuzz/fuzz-hostname-setup.c']],

        [['src/nspawn/fuzz-nspawn-settings.c'],
         [libshared,
          libnspawn_core],
         [libseccomp]],

        [['src/nspawn/fuzz-nspawn-oci.c'],
         [libshared,
          libnspawn_core],
         [libseccomp]],

        [['src/fuzz/fuzz-calendarspec.c']],

        [['src/fuzz/fuzz-time-util.c']],

        [['src/xdg-autostart-generator/fuzz-xdg-desktop.c',
          'src/xdg-autostart-generator/xdg-autostart-service.h',
          'src/xdg-autostart-generator/xdg-autostart-service.c']],

        [['src/udev/fuzz-udev-rule-parse-value.c']],
]
