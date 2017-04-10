# -*- mode: meson -*-

awkscript = 'test-hashmap-ordered.awk'
test_hashmap_ordered_c = custom_target(
    'test-hashmap-ordered.c',
    input : [awkscript, 'test-hashmap-plain.c'],
    output : 'test-hashmap-ordered.c',
    command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
    capture : true)

test_include_dir = include_directories('.')

path = run_command('sh', ['-c', 'echo "$PATH"']).stdout()
test_env = environment()
test_env.set('SYSTEMD_KBD_MODEL_MAP', kbd_model_map)
test_env.set('SYSTEMD_LANGUAGE_FALLBACK_MAP', language_fallback_map)
test_env.set('PATH', path)
test_env.prepend('PATH', meson.build_root())

############################################################

generate_sym_test_py = find_program('generate-sym-test.py')

test_libsystemd_sym_c = custom_target(
  'test-libsystemd-sym.c',
  input : [libsystemd_sym_path] + systemd_headers,
  output : 'test-libsystemd-sym.c',
  command : [generate_sym_test_py, libsystemd_sym_path] + systemd_headers,
  capture : true)

############################################################

tests += [
  [['src/test/test-device-nodes.c'],
   [libshared],
   []],

  [['src/test/test-engine.c'],
   [libcore,
    libudev,
    libsystemd],
   [threads,
    librt,
    libseccomp,
    libselinux,
    libmount,
    libblkid]],

  [['src/test/test-job-type.c'],
   [libcore,
    libudev,
    libsystemd],
   [threads,
    librt,
    libseccomp,
    libselinux,
    libmount,
    libblkid]],

  [['src/test/test-ns.c'],
   [libcore,
    libudev,
    libsystemd],
   [threads,
    librt,
    libseccomp,
    libselinux,
    libmount,
    libblkid],
   '', 'unsafe'],

  [['src/test/test-loopback.c'],
   [libcore,
    libudev,
    libsystemd],
   [threads,
    librt,
    libseccomp,
    libselinux,
    libmount,
    libblkid]],

  [['src/test/test-hostname.c'],
   [libcore,
    libudev,
    libsystemd],
   [threads,
    librt,
    libseccomp,
    libselinux,
    libmount,
    libblkid],
   '', 'unsafe'],

  [['src/test/test-dns-domain.c'],
   [libcore,
    libsystemd_network],
   []],

  [['src/test/test-boot-timestamps.c'],
   [libshared],
   [],
   'ENABLE_EFI'],

  [['src/test/test-unit-name.c'],
   [libcore,
    libudev,
    libsystemd],
   [threads,
    librt,
    libseccomp,
    libselinux,
    libmount,
    libblkid]],

  [['src/test/test-unit-file.c'],
   [libcore,
    libudev,
    libsystemd],
   [threads,
    librt,
    libseccomp,
    libselinux,
    libmount,
    libblkid]],

  [['src/test/test-utf8.c'],
   [libshared],
   []],

  [['src/test/test-capability.c'],
   [libshared],
   [libcap]],

  [['src/test/test-async.c'],
   [libshared],
   []],

  [['src/test/test-locale-util.c'],
   [libshared],
   []],

  [['src/test/test-copy.c'],
   [libshared_static],
   []],

  [['src/test/test-sigbus.c'],
   [libshared],
   []],

  [['src/test/test-condition.c'],
   [libshared],
   []],

  [['src/test/test-fdset.c'],
   [libshared],
   []],

  [['src/test/test-fstab-util.c'],
   [libshared],
   []],

  [['src/test/test-ratelimit.c'],
   [libshared],
   []],

  [['src/test/test-util.c'],
   [libshared],
   []],

  [['src/test/test-mount-util.c'],
   [libshared],
   []],

  [['src/test/test-exec-util.c'],
   [libshared],
   []],

  [['src/test/test-hexdecoct.c'],
   [libshared],
   []],

  [['src/test/test-alloc-util.c'],
   [libshared],
   []],

  [['src/test/test-xattr-util.c'],
   [libshared],
   []],

  [['src/test/test-io-util.c'],
   [libshared],
   []],

  [['src/test/test-glob-util.c'],
   [libshared],
   []],

  [['src/test/test-fs-util.c'],
   [libshared],
   []],

  [['src/test/test-proc-cmdline.c'],
   [libshared],
   []],

  [['src/test/test-fd-util.c'],
   [libshared],
   []],

  [['src/test/test-web-util.c'],
   [libshared],
   []],

  [['src/test/test-cpu-set-util.c'],
   [libshared],
   []],

  [['src/test/test-stat-util.c'],
   [libshared],
   []],

  [['src/test/test-escape.c'],
   [libshared],
   []],

  [['src/test/test-string-util.c'],
   [libshared],
   []],

  [['src/test/test-extract-word.c'],
   [libshared],
   []],

  [['src/test/test-parse-util.c'],
   [libshared],
   []],

  [['src/test/test-user-util.c'],
   [libshared],
   []],

  [['src/test/test-hostname-util.c'],
   [libshared],
   []],

  [['src/test/test-process-util.c'],
   [libshared],
   []],

  [['src/test/test-terminal-util.c'],
   [libshared],
   []],

  [['src/test/test-path-lookup.c'],
   [libshared],
   []],

  [['src/test/test-uid-range.c'],
   [libshared],
   []],

  [['src/test/test-cap-list.c',
    generated_gperf_headers],
   [libshared],
   [libcap]],

  [['src/test/test-socket-util.c'],
   [libshared],
   []],

  [['src/test/test-barrier.c'],
   [libshared],
   []],

  [['src/test/test-tmpfiles.c'],
   [libshared],
   []],

  [['src/test/test-namespace.c'],
   [libcore,
    libudev,
    libsystemd],
   [libblkid]],

  [['src/test/test-verbs.c'],
   [libshared],
   []],

  [['src/test/test-install-root.c'],
   [libshared],
   []],

  [['src/test/test-acl-util.c'],
   [libshared],
   [],
   'HAVE_ACL'],

  [['src/test/test-seccomp.c'],
   [libshared],
   [libseccomp],
   'HAVE_SECCOMP'],

  [['src/test/test-rlimit-util.c'],
   [libshared],
   []],

  [['src/test/test-ask-password-api.c'],
   [libshared],
   [],
   '', 'manual'],

  [['src/test/test-dissect-image.c'],
   [libshared],
   [libblkid],
   '', 'manual'],

  [['src/test/test-signal-util.c'],
   [libshared],
   []],

  [['src/test/test-selinux.c'],
   [libshared],
   []],

  [['src/test/test-sizeof.c'],
   [],
   []],

  [['src/test/test-hashmap.c',
    'src/test/test-hashmap-plain.c',
    test_hashmap_ordered_c],
   [libshared],
   []],

  [['src/test/test-set.c'],
   [libshared],
   []],

  [['src/test/test-bitmap.c'],
   [libshared],
   []],

  [['src/test/test-xml.c'],
   [libshared],
   []],

  [['src/test/test-list.c'],
   [libshared],
   []],

  [['src/test/test-unaligned.c'],
   [libshared],
   []],

  [['src/test/test-tables.c',
    'src/shared/test-tables.h',
    'src/journal/journald-server.c',
    'src/journal/journald-server.h'],
   [libcore,
    libjournal_core,
    libudev_core,
    libudev_internal,
    libsystemd_network],
   [threads,
    libseccomp,
    libmount,
    libxz,
    liblz4],
   '', '', [], libudev_core_includes],

  [['src/test/test-prioq.c'],
   [libshared],
   []],

  [['src/test/test-fileio.c'],
   [libshared],
   []],

  [['src/test/test-time.c'],
   [libshared],
   []],

  [['src/test/test-clock.c'],
   [libshared],
   []],

  [['src/test/test-architecture.c'],
   [libshared],
   []],

  [['src/test/test-log.c'],
   [libshared],
   []],

  [['src/test/test-ipcrm.c'],
   [libshared],
   [],
   '', 'unsafe'],

  [['src/test/test-btrfs.c'],
   [libshared],
   [],
   '', 'manual'],


  [['src/test/test-firewall-util.c'],
   [libfirewall,
    libshared],
   [],
   'HAVE_LIBIPTC'],

  [['src/test/test-netlink-manual.c'],
   [libshared],
   [libkmod],
   '', 'manual'],

  [['src/test/test-ellipsize.c'],
   [libshared],
   []],

  [['src/test/test-date.c'],
   [libshared],
   []],

  [['src/test/test-sleep.c'],
   [libshared],
   []],

  [['src/test/test-replace-var.c'],
   [libshared],
   []],

  [['src/test/test-calendarspec.c'],
   [libshared],
   []],

  [['src/test/test-strip-tab-ansi.c'],
   [libshared],
   []],

  [['src/test/test-daemon.c'],
   [libshared],
   []],

  [['src/test/test-cgroup.c'],
   [libshared],
   [],
   '', 'manual'],


  [['src/test/test-cgroup-mask.c'],
   [libcore,
    libudev,
    libsystemd],
   [threads,
    librt,
    libseccomp,
    libselinux,
    libmount,
    libblkid]],

  [['src/test/test-cgroup-util.c'],
   [libshared],
   []],

  [['src/test/test-env-util.c'],
   [libshared],
   []],

  [['src/test/test-strbuf.c'],
   [libshared],
   []],

  [['src/test/test-strv.c'],
   [libshared],
   []],

  [['src/test/test-path-util.c'],
   [libshared],
   []],

  [['src/test/test-path.c'],
   [libcore,
    libudev,
    libsystemd],
   [threads,
    librt,
    libseccomp,
    libselinux,
    libmount,
    libblkid]],

  [['src/test/test-execute.c'],
   [libcore,
    libudev,
    libsystemd],
   [threads,
    librt,
    libseccomp,
    libselinux,
    libmount,
    libblkid]],

  [['src/test/test-siphash24.c'],
   [libshared],
   []],

  [['src/test/test-strxcpyx.c'],
   [libshared],
   []],

  [['src/test/test-install.c'],
   [libcore,
    libsystemd],
   [],
   '', 'manual'],

  [['src/test/test-watchdog.c'],
   [libshared],
   []],

  [['src/test/test-sched-prio.c'],
   [libcore,
    libudev,
    libsystemd],
   [threads,
    librt,
    libseccomp,
    libselinux,
    libmount,
    libblkid]],

  [['src/test/test-conf-files.c'],
   [libshared],
   []],

  [['src/test/test-conf-parser.c'],
   [libshared],
   []],

  [['src/test/test-af-list.c',
    generated_gperf_headers],
   [libshared],
   []],

  [['src/test/test-arphrd-list.c',
    generated_gperf_headers],
   [libshared],
   []],

  [['src/test/test-journal-importer.c'],
   [libshared],
   []],

  [['src/test/test-libudev.c'],
   [libshared],
   []],

  [['src/test/test-udev.c'],
   [libudev_core,
    libudev_internal,
    libsystemd_network,
    libshared],
   [librt,
    libblkid,
    libkmod,
    libacl],
   '', 'manual'],

  [['src/test/test-id128.c'],
   [libshared],
   []],

  [['src/test/test-hash.c'],
   [libshared],
   []],

  [['src/test/test-nss.c'],
   [libshared],
   [libdl],
   '', 'manual'],
  ]

############################################################

# define some tests here, because the link_with deps were not defined earlier

tests += [
  [['src/journal/test-journal.c'],
   [libjournal_core],
   [threads,
    libxz,
    liblz4]],

  [['src/journal/test-journal-send.c'],
   [libjournal_core,
    libshared],
   []],

  [['src/journal/test-journal-syslog.c'],
   [libjournal_core,
    libshared],
   [threads,
    libxz,
    liblz4]],

  [['src/journal/test-journal-match.c'],
   [libshared],
   [threads,
    libxz,
    liblz4]],

  [['src/journal/test-journal-enum.c'],
   [libshared],
   []],

  [['src/journal/test-journal-stream.c'],
   [libshared],
   [threads,
    libxz,
    liblz4]],

  [['src/journal/test-journal-flush.c'],
   [libshared],
   [threads,
    libxz,
    liblz4]],

  [['src/journal/test-journal-init.c'],
   [libshared],
   [threads,
    libxz,
    liblz4]],

  [['src/journal/test-journal-verify.c'],
   [libshared],
   [threads,
    libxz,
    liblz4]],

  [['src/journal/test-journal-interleaving.c'],
   [libshared],
   [threads,
    libxz,
    liblz4]],

  [['src/journal/test-mmap-cache.c'],
   [libshared],
   []],

  [['src/journal/test-catalog.c'],
   [libshared],
   [],
   '', '', '-DCATALOG_DIR="@0@"'.format(build_catalog_dir)],

  [['src/journal/test-compress.c'],
   [libshared],
   [liblz4,
    libxz]],

  [['src/journal/test-compress-benchmark.c'],
   [libshared],
   [liblz4,
    libxz]],

  [['src/journal/test-audit-type.c'],
   [libshared],
   []],
  ]

############################################################

tests += [
  [['src/libsystemd/sd-bus/test-bus-error.c'],
   [libshared_static,
    libsystemd],
   []],
  ]

############################################################

tests += [
  [['src/libsystemd-network/test-dhcp-option.c',
    'src/libsystemd-network/dhcp-protocol.h',
    'src/libsystemd-network/dhcp-internal.h'],
   [libshared,
    libsystemd_network],
   []],

  [['src/libsystemd-network/test-dhcp-client.c',
    'src/libsystemd-network/dhcp-protocol.h',
    'src/libsystemd-network/dhcp-internal.h',
    'src/systemd/sd-dhcp-client.h'],
   [libshared,
    libsystemd_network],
   []],

  [['src/libsystemd-network/test-dhcp-server.c'],
   [libshared,
    libsystemd_network],
   []],

  [['src/libsystemd-network/test-ipv4ll.c',
    'src/libsystemd-network/arp-util.h',
    'src/systemd/sd-ipv4ll.h'],
   [libshared,
    libsystemd_network],
   []],

  [['src/libsystemd-network/test-ipv4ll-manual.c',
    'src/systemd/sd-ipv4ll.h'],
   [libshared,
    libsystemd_network],
   [],
   '', 'manual'],

  [['src/libsystemd-network/test-acd.c',
    'src/systemd/sd-ipv4acd.h'],
   [libshared,
    libsystemd_network],
   [],
   '', 'manual'],

  [['src/libsystemd-network/test-ndisc-rs.c',
    'src/libsystemd-network/dhcp-identifier.h',
    'src/libsystemd-network/dhcp-identifier.c',
    'src/libsystemd-network/icmp6-util.h',
    'src/systemd/sd-dhcp6-client.h',
    'src/systemd/sd-ndisc.h'],
   [libshared,
    libsystemd_network,
    libudev],
   []],

  [['src/libsystemd-network/test-dhcp6-client.c',
    'src/libsystemd-network/dhcp-identifier.h',
    'src/libsystemd-network/dhcp-identifier.c',
    'src/libsystemd-network/dhcp6-internal.h',
    'src/systemd/sd-dhcp6-client.h'],
   [libshared,
    libsystemd_network,
    libudev],
   []],

  [['src/libsystemd-network/test-lldp.c'],
   [libshared,
    libsystemd_network],
   []],
  ]

############################################################

tests += [
  [['src/login/test-login-shared.c'],
   [libshared],
   []],

  [['src/login/test-inhibit.c'],
   [libshared],
   [],
   '', 'manual'],

  [['src/login/test-login-tables.c'],
   [liblogind_core,
    libshared],
   []],
  ]
