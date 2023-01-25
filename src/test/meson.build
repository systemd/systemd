# SPDX-License-Identifier: LGPL-2.1-or-later

awkscript = 'test-hashmap-ordered.awk'
test_hashmap_ordered_c = custom_target(
        'test-hashmap-ordered.c',
        input : [awkscript, 'test-hashmap-plain.c'],
        output : 'test-hashmap-ordered.c',
        command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
        capture : true,
        build_by_default : want_tests != 'false')

test_include_dir = include_directories('.')

path = run_command(sh, '-c', 'echo "$PATH"', check: true).stdout().strip()
test_env = environment()
test_env.set('SYSTEMD_LANGUAGE_FALLBACK_MAP', language_fallback_map)
test_env.set('PATH', project_build_root + ':' + path)
test_env.set('PROJECT_BUILD_ROOT', project_build_root)

############################################################

generate_sym_test_py = find_program('generate-sym-test.py')

test_libsystemd_sym_c = custom_target(
        'test-libsystemd-sym.c',
        input : [libsystemd_sym_path] + systemd_headers,
        output : 'test-libsystemd-sym.c',
        command : [generate_sym_test_py, libsystemd_sym_path] + systemd_headers,
        capture : true,
        build_by_default : want_tests != 'false')

test_libudev_sym_c = custom_target(
        'test-libudev-sym.c',
        input : [libudev_sym_path, libudev_h_path],
        output : 'test-libudev-sym.c',
        command : [generate_sym_test_py, '@INPUT0@', '@INPUT1@'],
        capture : true,
        build_by_default : want_tests != 'false')

test_dlopen_c = files('test-dlopen.c')

############################################################

tests += [
        { 'sources' : files('test-argv-util.c') },

        { 'sources' : files('test-device-nodes.c') },

        { 'sources' : files('test-ether-addr-util.c') },

        { 'sources' : files('test-engine.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [threads, librt, libseccomp, libselinux, libmount, libblkid],
          'includes' : core_includes },

        { 'sources' : files('test-manager.c'),
          'link_with' : [libcore, libshared],
          'includes' : core_includes },

        { 'sources' : files('test-emergency-action.c'),
          'link_with' : [libcore, libshared],
          'includes' : core_includes },

        { 'sources' : files('test-chown-rec.c'),
          'link_with' : [libcore, libshared],
          'includes' : core_includes },

        { 'sources' : files('test-dlopen-so.c'),
          'dependencies' : libp11kit_cflags },

        { 'sources' : files('test-job-type.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [threads, librt, libseccomp, libselinux, libmount, libblkid],
          'includes' : core_includes },

        { 'sources' : files('test-ns.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [threads, librt, libseccomp, libselinux, libmount, libblkid],
          'includes' : core_includes,
          'type' : 'manual' },

        { 'sources' : files('test-loopback.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [threads, librt, libseccomp, libselinux, libmount, libblkid],
          'includes' : core_includes },

        { 'sources' : files('test-dns-domain.c') },

        { 'sources' : files('test-boot-timestamps.c'),
          'condition' : 'ENABLE_EFI' },

        { 'sources' : files('test-unit-file.c') },

        { 'sources' : files('test-unit-name.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [threads, librt, libseccomp, libselinux, libmount, libblkid],
          'includes' : core_includes },

        { 'sources' : files('test-load-fragment.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [threads, librt, libseccomp, libselinux, libmount, libblkid],
          'includes' : core_includes },

        { 'sources' : files('test-serialize.c') },

        { 'sources' : files('test-unit-serialize.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [threads, librt, libseccomp, libselinux, libmount, libblkid],
          'includes' : core_includes },

        { 'sources' : files('test-utf8.c') },

        { 'sources' : files('test-kbd-util.c') },

        { 'sources' : files('test-blockdev-util.c') },

        { 'sources' : files('test-dev-setup.c') },

        { 'sources' : files('test-capability.c'),
          'dependencies' : libcap },

        { 'sources' : files('test-async.c'),
          'timeout' : 120 },
        { 'sources' : files('test-locale-util.c') },

        { 'sources' : files('test-copy.c') },

        { 'sources' : files('test-recurse-dir.c') },

        { 'sources' : files('test-compress.c'),
          'link_with' : [libshared, libbasic_compress] },

        { 'sources' : files('test-compress-benchmark.c'),
          'link_with' : [libshared, libbasic_compress],
          'timeout' : 90 },

        { 'sources' : files('test-data-fd-util.c') },

        { 'sources' : files('test-static-destruct.c') },

        { 'sources' : files('test-sigbus.c') },

        { 'sources' : files('test-condition.c') },

        { 'sources' : files('test-fdset.c') },

        { 'sources' : files('test-fstab-util.c') },

        { 'sources' : files('test-random-util.c'),
          'dependencies' : libm,
          'timeout' : 120 },

        { 'sources' : files('test-format-table.c') },

        { 'sources' : files('test-format-util.c') },

        { 'sources' : files('test-ratelimit.c') },

        { 'sources' : files('test-raw-clone.c') },

        { 'sources' : files('test-limits-util.c') },

        { 'sources' : files('test-logarithm.c') },

        { 'sources' : files('test-macro.c') },

        { 'sources' : files('test-math-util.c'),
          'dependencies' : libm },

        { 'sources' : files('test-memory-util.c') },

        { 'sources' : files('test-mkdir.c') },

        { 'sources' : files('test-json.c'),
          'dependencies' : libm },

        { 'sources' : files('test-modhex.c') },

        { 'sources' : files('test-libmount.c'),
          'dependencies' : [threads, libmount] },

        { 'sources' : files('test-mount-util.c') },

        { 'sources' : files('test-mountpoint-util.c') },

        { 'sources' : files('test-exec-util.c') },

        { 'sources' : files('test-execve.c') },

        { 'sources' : files('test-hexdecoct.c') },

        { 'sources' : files('test-alloc-util.c') },

        { 'sources' : files('test-xattr-util.c') },

        { 'sources' : files('test-io-util.c') },

        { 'sources' : files('test-glob-util.c') },

        { 'sources' : files('test-fs-util.c') },

        { 'sources' : files('test-install-file.c') },

        { 'sources' : files('test-umask-util.c') },

        { 'sources' : files('test-creds.c') },

        { 'sources' : files('test-proc-cmdline.c') },

        { 'sources' : files('test-fd-util.c'),
          'dependencies' : libseccomp },

        { 'sources' : files('test-web-util.c') },

        { 'sources' : files('test-cpu-set-util.c') },

        { 'sources' : files('test-stat-util.c') },

        { 'sources' : files('test-devnum-util.c') },

        { 'sources' : files('test-os-util.c') },

        { 'sources' : files('test-libcrypt-util.c'),
          'dependencies': libcrypt,
          'timeout' : 120 },

        { 'sources' : files('test-escape.c') },

        { 'sources' : files('test-exit-status.c') },

        { 'sources' : files('test-specifier.c') },

        { 'sources' : files('test-string-util.c') },

        { 'sources' : files('test-extract-word.c') },

        { 'sources' : files('test-parse-argument.c') },

        { 'sources' : files('test-parse-helpers.c') },

        { 'sources' : files('test-parse-util.c'),
          'dependencies' : libm },

        { 'sources' : files('test-sysctl-util.c') },

        { 'sources' : files('test-import-util.c') },

        { 'sources' : files('test-uid-alloc-range.c') },

        { 'sources' : files('test-user-util.c') },

        { 'sources' : files('test-hostname-setup.c') },

        { 'sources' : files('test-hostname-util.c') },

        { 'sources' : files('test-process-util.c') },

        { 'sources' : files('test-terminal-util.c') },

        { 'sources' : files('test-path-lookup.c') },

        { 'sources' : files('test-pretty-print.c') },

        { 'sources' : files('test-uid-range.c') },

        { 'sources' : files('test-cap-list.c') + generated_gperf_headers,
          'dependencies' : libcap },

        { 'sources' : files('test-socket-util.c') },

        { 'sources' : files('test-socket-netlink.c') },

        { 'sources' : files('test-in-addr-util.c') },

        { 'sources' : files('test-in-addr-prefix-util.c') },

        { 'sources' : files('test-barrier.c') },

        { 'sources' : files('test-tmpfiles.c') },

        { 'sources' : files('test-namespace.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [threads, libblkid],
          'includes' : core_includes },

        { 'sources' : files('test-verbs.c') },

        { 'sources' : files('test-install-root.c') },

        { 'sources' : files('test-acl-util.c'),
          'condition' : 'HAVE_ACL' },

        { 'sources' : files('test-seccomp.c'),
          'dependencies' : libseccomp,
          'condition' : 'HAVE_SECCOMP' },

        { 'sources' : files('test-rlimit-util.c') },

        { 'sources' : files('test-ask-password-api.c'),
          'type' : 'manual' },

        { 'sources' : files('test-signal-util.c') },

        { 'sources' : files('test-loop-block.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [threads, libblkid],
          'includes' : core_includes,
          'parallel' : false },

        { 'sources' : files('test-selinux.c') },

        { 'sources' : files('test-sizeof.c'),
          'link_with' : libbasic },

        { 'sources' : files('test-bpf-devices.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [libmount, threads, librt, libseccomp, libselinux, libblkid],
          'includes' : core_includes },

        { 'sources' : files('test-bpf-firewall.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [libmount, threads, librt, libseccomp, libselinux, libblkid],
          'includes' : core_includes },

        { 'sources' : files('test-bpf-foreign-programs.c'),
          'link_with' : [libcore, libshared],
          'includes' : core_includes },

        { 'sources' : files('test-bpf-lsm.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [libmount, threads, librt, libseccomp, libselinux, libblkid],
          'includes' : core_includes },

        { 'sources' : files('test-watch-pid.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [libmount, threads, librt, libseccomp, libselinux, libblkid],
          'includes' : core_includes },

        { 'sources' : files('test-hashmap.c', 'test-hashmap-plain.c') + [test_hashmap_ordered_c],
          'timeout' : 180 },

        { 'sources' : files('test-set.c') },

        { 'sources' : files('test-ordered-set.c') },

        { 'sources' : files('test-set-disable-mempool.c'),
          'dependencies' : threads },

        { 'sources' : files('test-hash-funcs.c') },

        { 'sources' : files('test-bitmap.c') },

        { 'sources' : files('test-xml.c') },

        { 'sources' : files('test-list.c') },

        { 'sources' : files('test-procfs-util.c') },

        { 'sources' : files('test-unaligned.c') },

        { 'sources' : files('test-tables.c'),
          'link_with' : [libcore, libjournal_core, libudevd_core, libshared],
          'dependencies' : [threads, libseccomp, libmount, libxz, liblz4, libblkid, libselinux],
          'includes' : [core_includes, journal_includes, udev_includes] },

        { 'sources' : files('test-prioq.c') },

        { 'sources' : files('test-fileio.c') },

        { 'sources' : files('test-time-util.c') },

        { 'sources' : files('test-clock.c') },

        { 'sources' : files('test-tmpfile-util.c') },

        { 'sources' : files('test-architecture.c') },

        { 'sources' : files('test-gpt.c') },

        { 'sources' : files('test-log.c') },

        { 'sources' : files('test-ipcrm.c'),
          'type' : 'unsafe' },

        { 'sources' : files('test-btrfs.c'),
          'type' : 'manual' },

        { 'sources' : files('test-firewall-util.c') },

        { 'sources' : files('test-net-naming-scheme.c') },

        { 'sources' : files('test-netlink-manual.c'),
          'dependencies' : libkmod,
          'condition' : 'HAVE_KMOD',
          'type' : 'manual' },

        { 'sources' : files('test-ellipsize.c') },

        { 'sources' : files('test-date.c') },

        { 'sources' : files('test-sbat.c'),
          'condition' : 'HAVE_GNU_EFI',
          'c_args' : '-I@0@'.format(efi_config_h_dir) },

        { 'sources' : files('test-sleep.c') },

        { 'sources' : files('test-tpm2.c') },

        { 'sources' : files('test-replace-var.c') },

        { 'sources' : files('test-calendarspec.c') },

        { 'sources' : files('test-strip-tab-ansi.c') },

        { 'sources' : files('test-coredump-util.c') },

        { 'sources' : files('test-daemon.c') },

        { 'sources' : files('test-cgroup.c') },

        { 'sources' : files('test-cgroup-cpu.c'),
          'link_with' : [libcore, libshared],
          'includes' : core_includes },

        { 'sources' : files('test-cgroup-unit-default.c'),
          'link_with' : [libcore, libshared],
          'includes' : core_includes },

        { 'sources' : files('test-cgroup-mask.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [threads, librt, libseccomp, libselinux, libmount, libblkid],
          'includes' : core_includes },

        { 'sources' : files('test-varlink.c'),
          'dependencies' : threads },

        { 'sources' : files('test-cgroup-util.c') },

        { 'sources' : files('test-cgroup-setup.c') },

        { 'sources' : files('test-env-file.c') },

        { 'sources' : files('test-env-util.c') },

        { 'sources' : files('test-strbuf.c') },

        { 'sources' : files('test-bootspec.c') },

        { 'sources' : files('test-strv.c') },

        { 'sources' : files('test-nulstr-util.c') },

        { 'sources' : files('test-path-util.c') },

        { 'sources' : files('test-rm-rf.c') },

        { 'sources' : files('test-chase-symlinks.c'),
          'type' : 'manual' },

        { 'sources' : files('test-path.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [threads, librt, libseccomp, libselinux, libmount, libblkid],
          'includes' : core_includes,
          'timeout' : 120 },

        { 'sources' : files('test-execute.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [threads, librt, libseccomp, libselinux, libmount, libblkid],
          'includes' : core_includes,
          'timeout' : 360 },

        { 'sources' : files('test-siphash24.c') },

        { 'sources' : files('test-strxcpyx.c') },

        { 'sources' : files('test-install.c'),
          'link_with' : [libcore, libshared],
          'includes' : core_includes,
          'type' : 'manual' },

        { 'sources' : files('test-watchdog.c'),
          'type' : 'unsafe' },

        { 'sources' : files('test-sched-prio.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : [threads, librt, libseccomp, libselinux, libmount, libblkid],
          'includes' : core_includes },

        { 'sources' : files('test-conf-files.c') },

        { 'sources' : files('test-conf-parser.c') },

        { 'sources' : files('test-af-list.c') + generated_gperf_headers },

        { 'sources' : files('test-arphrd-util.c') + generated_gperf_headers },

        { 'sources' : files('test-errno-list.c') + generated_gperf_headers },

        { 'sources' : files('test-errno-util.c') },

        { 'sources' : files('test-ip-protocol-list.c') + shared_generated_gperf_headers },

        { 'sources' : files('test-journal-importer.c') },

        { 'sources' : files('test-utmp.c'),
          'condition' : 'ENABLE_UTMP' },

        { 'sources' : files('test-udev.c'),
          'link_with' : [libudevd_core, libshared],
          'dependencies' : [threads, librt, libblkid, libkmod, libacl, libselinux],
          'includes' : udev_includes,
          'type' : 'manual' },

        { 'sources' : files('test-udev-util.c') },

        { 'sources' : files('test-id128.c') },

        { 'sources' : files('test-cryptolib.c'),
          'link_with' : libshared,
          'dependencies' : lib_openssl_or_gcrypt,
          'condition' : 'HAVE_OPENSSL_OR_GCRYPT' },

        { 'sources' : files('test-nss-hosts.c', 'nss-test-util.c'),
          'dependencies' : libdl,
          'condition' : 'ENABLE_NSS',
          'timeout' : 120 },

        { 'sources' : files('test-nss-users.c', 'nss-test-util.c'),
          'dependencies' : libdl,
          'condition' : 'ENABLE_NSS' },

        { 'sources' : files('test-bus-util.c') },

        { 'sources' : files('test-percent-util.c') },

        { 'sources' : files('test-sd-hwdb.c') },

        { 'sources' : files('test-sd-path.c') },

        { 'sources' : files('test-local-addresses.c') },

        { 'sources' : files('test-psi-util.c') },

        { 'sources' : files('test-qrcode-util.c'),
          'dependencies' : libdl },

        { 'sources' : files('test-nscd-flush.c'),
          'condition' : 'ENABLE_NSCD',
          'type' : 'manual' },

        { 'sources' : files('test-hmac.c') },

        { 'sources' : files('test-sha256.c') },

        { 'sources' : files('test-open-file.c') },
]

############################################################

# define some tests here, because the link_with deps were not defined earlier

tests += [
        { 'sources' : files('../libsystemd/sd-bus/test-bus-error.c'),
          'link_with' : [libshared_static, libsystemd_static] },

        { 'sources' : files('../libsystemd/sd-device/test-sd-device-thread.c'),
          'link_with' : libsystemd,
          'dependencies' : threads },

        { 'sources' : files('../libudev/test-udev-device-thread.c'),
          'link_with' : libudev,
          'dependencies' : threads },

        { 'sources' : files('test-socket-bind.c'),
          'link_with' : [libcore, libshared],
          'dependencies' : libdl,
          'includes' : core_includes,
          'condition' : 'BPF_FRAMEWORK' },
]
