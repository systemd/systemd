# SPDX-License-Identifier: LGPL-2.1-or-later

awkscript = 'test-hashmap-ordered.awk'
test_hashmap_ordered_c = custom_target(
        'test-hashmap-ordered.c',
        input : [awkscript, 'test-hashmap-plain.c'],
        output : 'test-hashmap-ordered.c',
        command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
        capture : true,
        build_by_default : want_tests != 'false')

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

simple_tests += files(
        'test-alloc-util.c',
        'test-architecture.c',
        'test-argv-util.c',
        'test-barrier.c',
        'test-bitfield.c',
        'test-bitmap.c',
        'test-blockdev-util.c',
        'test-bootspec.c',
        'test-bus-util.c',
        'test-calendarspec.c',
        'test-cgroup-setup.c',
        'test-cgroup-util.c',
        'test-cgroup.c',
        'test-clock.c',
        'test-compare-operator.c',
        'test-condition.c',
        'test-conf-files.c',
        'test-conf-parser.c',
        'test-copy.c',
        'test-coredump-util.c',
        'test-cpu-set-util.c',
        'test-creds.c',
        'test-daemon.c',
        'test-data-fd-util.c',
        'test-date.c',
        'test-dev-setup.c',
        'test-device-nodes.c',
        'test-devnum-util.c',
        'test-dns-domain.c',
        'test-ellipsize.c',
        'test-env-file.c',
        'test-env-util.c',
        'test-errno-util.c',
        'test-escape.c',
        'test-ether-addr-util.c',
        'test-exec-util.c',
        'test-execve.c',
        'test-exit-status.c',
        'test-extract-word.c',
        'test-fdset.c',
        'test-fileio.c',
        'test-firewall-util.c',
        'test-format-table.c',
        'test-format-util.c',
        'test-fs-util.c',
        'test-fstab-util.c',
        'test-glob-util.c',
        'test-gpt.c',
        'test-hash-funcs.c',
        'test-hexdecoct.c',
        'test-hmac.c',
        'test-hostname-setup.c',
        'test-hostname-util.c',
        'test-id128.c',
        'test-import-util.c',
        'test-in-addr-prefix-util.c',
        'test-in-addr-util.c',
        'test-install-file.c',
        'test-install-root.c',
        'test-io-util.c',
        'test-journal-importer.c',
        'test-kbd-util.c',
        'test-limits-util.c',
        'test-list.c',
        'test-local-addresses.c',
        'test-locale-util.c',
        'test-lock-util.c',
        'test-log.c',
        'test-logarithm.c',
        'test-macro.c',
        'test-memory-util.c',
        'test-mempool.c',
        'test-mkdir.c',
        'test-modhex.c',
        'test-mount-util.c',
        'test-mountpoint-util.c',
        'test-net-naming-scheme.c',
        'test-nulstr-util.c',
        'test-open-file.c',
        'test-ordered-set.c',
        'test-os-util.c',
        'test-parse-argument.c',
        'test-parse-helpers.c',
        'test-path-lookup.c',
        'test-path-util.c',
        'test-percent-util.c',
        'test-pretty-print.c',
        'test-prioq.c',
        'test-proc-cmdline.c',
        'test-procfs-util.c',
        'test-psi-util.c',
        'test-ratelimit.c',
        'test-raw-clone.c',
        'test-recurse-dir.c',
        'test-replace-var.c',
        'test-rlimit-util.c',
        'test-rm-rf.c',
        'test-sd-hwdb.c',
        'test-sd-path.c',
        'test-selinux.c',
        'test-serialize.c',
        'test-set.c',
        'test-sha256.c',
        'test-sigbus.c',
        'test-signal-util.c',
        'test-siphash24.c',
        'test-sleep.c',
        'test-socket-netlink.c',
        'test-socket-util.c',
        'test-specifier.c',
        'test-stat-util.c',
        'test-static-destruct.c',
        'test-strbuf.c',
        'test-string-util.c',
        'test-strip-tab-ansi.c',
        'test-strv.c',
        'test-strxcpyx.c',
        'test-sysctl-util.c',
        'test-terminal-util.c',
        'test-tmpfile-util.c',
        'test-tpm2.c',
        'test-udev-util.c',
        'test-uid-alloc-range.c',
        'test-uid-range.c',
        'test-umask-util.c',
        'test-unaligned.c',
        'test-unit-file.c',
        'test-user-util.c',
        'test-utf8.c',
        'test-variadic.c',
        'test-verbs.c',
        'test-web-util.c',
        'test-xattr-util.c',
        'test-xml.c',
)

############################################################

common_test_dependencies = [
        libblkid,
        libmount,
        librt,
        libseccomp,
        libselinux,
        threads,
]

tests += [
        {
                'sources' : files('test-acl-util.c'),
                'condition' : 'HAVE_ACL',
        },
        {
                'sources' : [
                        files('test-af-list.c'),
                        generated_gperf_headers,
                ],
        },
        {
                'sources' : [
                        files('test-arphrd-util.c'),
                        generated_gperf_headers,
                ],
        },
        {
                'sources' : files('test-ask-password-api.c'),
                'type' : 'manual',
        },
        {
                'sources' : files('test-async.c'),
                'timeout' : 120,
        },
        {
                'sources' : files('test-boot-timestamps.c'),
                'condition' : 'ENABLE_EFI',
        },
        {
                'sources' : files('test-bpf-devices.c'),
                'dependencies' : common_test_dependencies,
                'base' : test_core_base,
        },
        {
                'sources' : files('test-bpf-firewall.c'),
                'dependencies' : common_test_dependencies,
                'base' : test_core_base,
        },
        {
                'sources' : files('test-bpf-foreign-programs.c'),
                'base' : test_core_base,
        },
        {
                'sources' : files('test-bpf-lsm.c'),
                'dependencies' : common_test_dependencies,
                'base' : test_core_base,
        },
        {
                'sources' : files('test-btrfs.c'),
                'type' : 'manual',
        },
        {
                'sources' : [
                        files('test-cap-list.c'),
                        generated_gperf_headers,
                ],
                'dependencies' : libcap,
        },
        {
                'sources' : files('test-capability.c'),
                'dependencies' : libcap,
        },
        {
                'sources' : files('test-cgroup-cpu.c'),
                'base' : test_core_base,
        },
        {
                'sources' : files('test-cgroup-mask.c'),
                'dependencies' : common_test_dependencies,
                'base' : test_core_base,
        },
        {
                'sources' : files('test-cgroup-unit-default.c'),
                'base' : test_core_base,
        },
        {
                'sources' : files('test-chase.c'),
                'type' : 'manual',
        },
        {
                'sources' : files('test-chown-rec.c'),
                'base' : test_core_base,
        },
        {
                'sources' : files('test-compress-benchmark.c'),
                'link_with' : [
                        libbasic_compress,
                        libshared,
                ],
                'timeout' : 90,
        },
        {
                'sources' : files('test-compress.c'),
                'link_with' : [
                        libbasic_compress,
                        libshared,
                ],
        },
        {
                'sources' : files('test-cryptolib.c'),
                'link_with' : libshared,
                'dependencies' : lib_openssl_or_gcrypt,
                'condition' : 'HAVE_OPENSSL_OR_GCRYPT',
        },
        {
                'sources' : files('test-dlopen-so.c'),
                'dependencies' : libp11kit_cflags
        },
        {
                'sources' : files('test-emergency-action.c'),
                'base' : test_core_base,
        },
        {
                'sources' : files('test-engine.c'),
                'dependencies' : common_test_dependencies,
                'base' : test_core_base,
        },
        {
                'sources' : [
                        files('test-errno-list.c'),
                        generated_gperf_headers,
                ],
        },
        {
                'sources' : files('test-execute.c'),
                'dependencies' : common_test_dependencies,
                'base' : test_core_base,
                'timeout' : 360,
        },
        {
                'sources' : files('test-fd-util.c'),
                'dependencies' : libseccomp,
        },
        {
                'sources' : [files(
                        'test-hashmap.c',
                        'test-hashmap-plain.c'),
                        test_hashmap_ordered_c,
                ],
                'timeout' : 180,
        },
        {
                'sources' : files('test-install.c'),
                'base' : test_core_base,
                'type' : 'manual',
        },
        {
                'sources' : [
                        files('test-ip-protocol-list.c'),
                        shared_generated_gperf_headers,
                ],
        },
        {
                'sources' : files('test-ipcrm.c'),
                'type' : 'unsafe',
        },
        {
                'sources' : files('test-job-type.c'),
                'dependencies' : common_test_dependencies,
                'base' : test_core_base,
        },
        {
                'sources' : files('test-json.c'),
                'dependencies' : libm,
        },
        {
                'sources' : files('test-libcrypt-util.c'),
                'dependencies' : libcrypt,
                'timeout' : 120,
        },
        {
                'sources' : files('test-libmount.c'),
                'dependencies' : [
                        libmount,
                        threads,
                ],
        },
        {
                'sources' : files('test-load-fragment.c'),
                'dependencies' : common_test_dependencies,
                'base' : test_core_base,
        },
        {
                'sources' : files('test-loop-block.c'),
                'dependencies' : [threads, libblkid],
                'base' : test_core_base,
                'parallel' : false,
        },
        {
                'sources' : files('test-loopback.c'),
                'dependencies' : common_test_dependencies,
        },
        {
                'sources' : files('test-manager.c'),
                'base' : test_core_base,
        },
        {
                'sources' : files('test-math-util.c'),
                'dependencies' : libm,
        },
        {
                'sources' : files('test-mempress.c'),
                'dependencies' : threads,
        },
        {
                'sources' : files('test-namespace.c'),
                'dependencies' : [
                        libblkid,
                        threads,
                ],
                'base' : test_core_base,
        },
        {
                'sources' : files('test-netlink-manual.c'),
                'dependencies' : libkmod,
                'condition' : 'HAVE_KMOD',
                'type' : 'manual',
        },
        {
                'sources' : files('test-ns.c'),
                'dependencies' : common_test_dependencies,
                'base' : test_core_base,
                'type' : 'manual',
        },
        {
                'sources' : files('test-nscd-flush.c'),
                'condition' : 'ENABLE_NSCD',
                'type' : 'manual',
        },
        {
                'sources' : files(
                        'test-nss-hosts.c',
                        'nss-test-util.c',
                ),
                'dependencies' : libdl,
                'condition' : 'ENABLE_NSS',
                'timeout' : 120,
        },
        {
                'sources' : files(
                        'test-nss-users.c',
                        'nss-test-util.c',
                ),
                'dependencies' : libdl,
                'condition' : 'ENABLE_NSS',
        },
        {
                'sources' : files('test-parse-util.c'),
                'dependencies' : libm,
        },
        {
                'sources' : files('test-path.c'),
                'dependencies' : common_test_dependencies,
                'base' : test_core_base,
                'timeout' : 120,
        },
        {
                'sources' : files('test-process-util.c'),
                'dependencies' : threads,
        },
        {
                'sources' : files('test-qrcode-util.c'),
                'dependencies' : libdl,
        },
        {
                'sources' : files('test-random-util.c'),
                'dependencies' : libm,
                'timeout' : 120,
        },
        {
                'sources' : files('test-sbat.c'),
                'condition' : 'ENABLE_BOOTLOADER',
                'c_args' : '-I@0@'.format(efi_config_h_dir),
        },
        {
                'sources' : files('test-sched-prio.c'),
                'dependencies' : common_test_dependencies,
                'base' : test_core_base,
        },
        {
                'sources' : files('test-seccomp.c'),
                'dependencies' : libseccomp,
                'condition' : 'HAVE_SECCOMP',
        },
        {
                'sources' : files('test-set-disable-mempool.c'),
                'dependencies' : threads,
        },
        {
                'sources' : files('test-sizeof.c'),
                'link_with' : libbasic,
        },
        {
                'sources' : files('test-tables.c'),
                'link_with' : [
                        libcore,
                        libjournal_core,
                        libshared,
                        libudevd_core,
                ],
                'dependencies' : [
                        libblkid,
                        liblz4,
                        libmount,
                        libseccomp,
                        libselinux,
                        libxz,
                        threads,
                ],
                'includes' : [
                        core_includes,
                        journal_includes,
                        udev_includes,
                ],
        },
        {
                'sources' : files('test-time-util.c'),
                'timeout' : 120,
        },
        {
                'sources' : files('test-udev.c'),
                'link_with' : [
                        libshared,
                        libudevd_core,
                ],
                'dependencies' : [
                        libacl,
                        libblkid,
                        libkmod,
                        librt,
                        libselinux,
                        threads,
                ],
                'includes' : udev_includes,
                'type' : 'manual',
        },
        {
                'sources' : files('test-unit-name.c'),
                'dependencies' : common_test_dependencies,
                'base' : test_core_base,
        },
        {
                'sources' : files('test-unit-serialize.c'),
                'dependencies' : common_test_dependencies,
                'base' : test_core_base,
        },
        {
                'sources' : files('test-utmp.c'),
                'condition' : 'ENABLE_UTMP',
        },
        {
                'sources' : files('test-varlink.c'),
                'dependencies' : threads,
        },
        {
                'sources' : files('test-watch-pid.c'),
                'dependencies' : common_test_dependencies,
                'base' : test_core_base,
        },
        {
                'sources' : files('test-watchdog.c'),
                'type' : 'unsafe',
        },
]

############################################################

# define some tests here, because the link_with deps were not defined earlier

tests += [
        {
                'sources' : files('../libsystemd/sd-bus/test-bus-error.c'),
                'link_with' : [
                        libshared_static,
                        libsystemd_static,
                ],
        },
        {
                'sources' : files('../libsystemd/sd-device/test-sd-device-thread.c'),
                'link_with' : libsystemd,
                'dependencies' : threads,
        },
        {
                'sources' : files('../libudev/test-udev-device-thread.c'),
                'link_with' : libudev,
                'dependencies' : threads,
        },
        {
                'sources' : files('test-socket-bind.c'),
                'dependencies' : libdl,
                'condition' : 'BPF_FRAMEWORK',
                'base' : test_core_base,
        },
]
