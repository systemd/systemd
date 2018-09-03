# SPDX-License-Identifier: LGPL-2.1+

fuzzers += [
        [['src/fuzz/fuzz-dns-packet.c',
          dns_type_headers],
         [libsystemd_resolve_core,
          libshared],
         [libgcrypt,
          libgpg_error,
          libm]],

        [['src/fuzz/fuzz-dhcp-server.c'],
         [libsystemd_network,
          libshared],
         []],

        [['src/fuzz/fuzz-unit-file.c'],
         [libcore,
          libshared],
         [libmount]],

        [['src/fuzz/fuzz-journald-syslog.c'],
         [libjournal_core,
          libshared],
         [libselinux]],

        [['src/fuzz/fuzz-journal-remote.c'],
         [libsystemd_journal_remote,
          libshared],
         []],
]
