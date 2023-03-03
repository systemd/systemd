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

if efi_addon != ''
        test_env.set('EFI_ADDON', efi_addon)
endif

############################################################

generate_sym_test_py = find_program('generate-sym-test.py')

test_libsystemd_sym_c = custom_target(
        'test-libsystemd-sym.c',
        input : [libsystemd_sym_path] + systemd_headers + libsystemd_sources,
        output : 'test-libsystemd-sym.c',
        command : [generate_sym_test_py, libsystemd_sym_path, libsystemd_dir_path] + systemd_headers,
        capture : true,
        build_by_default : want_tests != 'false')

test_libudev_sym_c = custom_target(
        'test-libudev-sym.c',
        input : [libudev_sym_path, libudev_h_path] + libudev_sources,
        output : 'test-libudev-sym.c',
        command : [generate_sym_test_py, libudev_sym_path, libudev_dir_path, libudev_h_path],
        capture : true,
        build_by_default : want_tests != 'false')

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
        'test-chase.c',
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
        'test-fiemap.c',
        'test-fileio.c',
        'test-firewall-util.c',
        'test-format-table.c',
        'test-format-util.c',
        'test-fs-util.c',
        'test-fstab-util.c',
        'test-glob-util.c',
        'test-gpt.c',
        'test-gunicode.c',
        'test-hash-funcs.c',
        'test-hexdecoct.c',
        'test-hmac.c',
        'test-hostname-setup.c',
        'test-hostname-util.c',
        'test-id128.c',
        'test-image-policy.c',
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
        'test-memfd-util.c',
        'test-memory-util.c',
        'test-mempool.c',
        'test-memstream-util.c',
        'test-mkdir.c',
        'test-modhex.c',
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
        'test-secure-bits.c',
        'test-selinux.c',
        'test-serialize.c',
        'test-set.c',
        'test-sha256.c',
        'test-sigbus.c',
        'test-signal-util.c',
        'test-siphash24.c',
        'test-sleep-config.c',
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
        'test-udev-util.c',
        'test-uid-alloc-range.c',
        'test-uid-range.c',
        'test-umask-util.c',
        'test-unaligned.c',
        'test-unit-file.c',
        'test-user-util.c',
        'test-utf8.c',
        'test-verbs.c',
        'test-vpick.c',
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

executables += [
        test_template + {
                'sources' : files('test-acl-util.c'),
                'conditions' : ['HAVE_ACL'],
        },
        test_template + {
                'sources' : files('test-af-list.c') +
                            generated_gperf_headers,
        },
        test_template + {
                'sources' : files('test-arphrd-util.c') +
                            generated_gperf_headers,
        },
        test_template + {
                'sources' : files('test-ask-password-api.c'),
                'type' : 'manual',
        },
        test_template + {
                'sources' : files('test-async.c'),
                'timeout' : 120,
        },
        test_template + {
                'sources' : files('test-boot-timestamps.c'),
                'conditions' : ['ENABLE_EFI'],
        },
        test_template + {
                'sources' : files('test-btrfs.c'),
                'type' : 'manual',
        },
        test_template + {
                'sources' : files('test-btrfs-physical-offset.c'),
                'type' : 'manual',
        },
        test_template + {
                'sources' : files('test-cap-list.c') +
                            generated_gperf_headers,
                'dependencies' : libcap,
        },
        test_template + {
                'sources' : files('test-capability.c'),
                'dependencies' : libcap,
        },
        test_template + {
                'sources' : files('test-chase-manual.c'),
                'type' : 'manual',
        },
        test_template + {
                'sources' : files('test-compress-benchmark.c'),
                'link_with' : [
                        libbasic_compress,
                        libshared,
                ],
                'timeout' : 90,
        },
        test_template + {
                'sources' : files('test-compress.c'),
                'link_with' : [
                        libbasic_compress,
                        libshared,
                ],
        },
        test_template + {
                'sources' : files('test-cryptolib.c'),
                'dependencies' : lib_openssl_or_gcrypt,
                'conditions' : ['HAVE_OPENSSL_OR_GCRYPT'],
        },
        test_template + {
                'sources' : files('test-dlopen-so.c'),
                'dependencies' : libp11kit_cflags
        },
        test_template + {
                # only static linking apart from libdl, to make sure that the
                # module is linked to all libraries that it uses.
                'sources' : files('test-dlopen.c'),
                'link_with' : libbasic,
                'dependencies' : libdl,
                'install' : false,
                'type' : 'manual',
        },
        test_template + {
                'sources' : files('test-errno-list.c') +
                            generated_gperf_headers,
        },
        test_template + {
                'sources' : files('test-fd-util.c'),
                'dependencies' : libseccomp,
        },
        test_template + {
                'sources' : files(
                        'test-hashmap.c',
                        'test-hashmap-plain.c',
                ) + [
                        test_hashmap_ordered_c,
                ],
                'timeout' : 180,
        },
        test_template + {
                'sources' : files('test-ip-protocol-list.c') +
                            shared_generated_gperf_headers,
        },
        test_template + {
                'sources' : files('test-ipcrm.c'),
                'type' : 'unsafe',
        },
        test_template + {
                'sources' : files('test-json.c'),
                'dependencies' : libm,
        },
        test_template + {
                'sources' : files('test-libcrypt-util.c'),
                'dependencies' : libcrypt,
                'timeout' : 120,
        },
        test_template + {
                'sources' : files('test-libmount.c'),
                'dependencies' : [
                        libmount,
                        threads,
                ],
        },
        test_template + {
                'sources' : files('test-loopback.c'),
                'dependencies' : common_test_dependencies,
        },
        test_template + {
                'sources' : files('test-math-util.c'),
                'dependencies' : libm,
        },
        test_template + {
                'sources' : files('test-mempress.c'),
                'dependencies' : threads,
        },
        test_template + {
                'sources' : files('test-mount-util.c'),
                'dependencies' : libmount,
        },
        test_template + {
                'sources' : files('test-netlink-manual.c'),
                'dependencies' : libkmod,
                'conditions' : ['HAVE_KMOD'],
                'type' : 'manual',
        },
        test_template + {
                'sources' : files('test-nft-set.c'),
                'type' : 'manual',
        },
        test_template + {
                'sources' : files('test-nscd-flush.c'),
                'conditions' : ['ENABLE_NSCD'],
                'type' : 'manual',
        },
        test_template + {
                'sources' : files(
                        'test-nss-hosts.c',
                        'nss-test-util.c',
                ),
                'dependencies' : libdl,
                'conditions' : ['ENABLE_NSS'],
                'timeout' : 120,
        },
        test_template + {
                'sources' : files(
                        'test-nss-users.c',
                        'nss-test-util.c',
                ),
                'dependencies' : libdl,
                'conditions' : ['ENABLE_NSS'],
        },
        test_template + {
                'sources' : files('test-openssl.c'),
                'dependencies' : libopenssl,
                'conditions' : ['HAVE_OPENSSL'],
        },
        test_template + {
                'sources' : files('test-parse-util.c'),
                'dependencies' : libm,
        },
        test_template + {
                'sources' : files('test-process-util.c'),
                'dependencies' : threads,
        },
        test_template + {
                'sources' : files('test-qrcode-util.c'),
                'dependencies' : libdl,
        },
        test_template + {
                'sources' : files('test-random-util.c'),
                'dependencies' : libm,
                'timeout' : 120,
        },
        test_template + {
                'sources' : files('test-sbat.c'),
                'conditions' : ['ENABLE_BOOTLOADER'],
                'c_args' : '-I@0@'.format(efi_config_h_dir),
        },
        test_template + {
                'sources' : files('test-seccomp.c'),
                'dependencies' : libseccomp,
                'conditions' : ['HAVE_SECCOMP'],
        },
        test_template + {
                'sources' : files('test-set-disable-mempool.c'),
                'dependencies' : threads,
        },
        test_template + {
                'sources' : files('test-sizeof.c'),
                'link_with' : libbasic,
        },
        test_template + {
                'sources' : files('test-time-util.c'),
                'timeout' : 120,
        },
        test_template + {
                'sources' : files('test-tpm2.c'),
                'dependencies' : libopenssl,
                'timeout' : 120,
        },
        test_template + {
                'sources' : files('test-utmp.c'),
                'conditions' : ['ENABLE_UTMP'],
        },
        test_template + {
                'sources' : files('test-varlink.c'),
                'dependencies' : threads,
        },
        test_template + {
                'sources' : files('test-varlink-idl.c'),
                'dependencies' : threads,
        },
        test_template + {
                'sources' : files('test-watchdog.c'),
                'type' : 'unsafe',
        },

        # Symbol tests
        test_template + {
                'name' : 'test-libsystemd-sym',
                'sources' : test_libsystemd_sym_c,
                'link_with' : libsystemd,
                'suite' : 'libsystemd',
        },
        test_template + {
                'name' : 'test-libsystemd-static-sym',
                'sources' : test_libsystemd_sym_c,
                'link_with' : install_libsystemd_static,
                'build_by_default' : want_tests != 'false' and static_libsystemd != 'false',
                'install' : install_tests and static_libsystemd != 'false',
                'suite' : 'libsystemd',
        },
        test_template + {
                'name' : 'test-libudev-sym',
                'sources' : test_libudev_sym_c,
                'include_directories' : libudev_includes,
                'c_args' : ['-Wno-deprecated-declarations'] + test_cflags,
                'link_with' : libudev,
                'suite' : 'libudev',
        },
        test_template + {
                'name' : 'test-libudev-static-sym',
                'sources' : test_libudev_sym_c,
                'include_directories' : libudev_includes,
                'c_args' : ['-Wno-deprecated-declarations'] + test_cflags,
                'link_with' : install_libudev_static,
                'build_by_default' : want_tests != 'false' and static_libudev != 'false',
                'install' : install_tests and static_libudev != 'false',
                'suite' : 'libudev',
        },

        # Tests that link to libcore, i.e. tests for pid1 code.
        core_test_template + {
                'sources' : files('test-bpf-devices.c'),
                'dependencies' : common_test_dependencies,
        },
        core_test_template + {
                'sources' : files('test-bpf-firewall.c'),
                'dependencies' : common_test_dependencies,
        },
        core_test_template + {
                'sources' : files('test-bpf-foreign-programs.c'),
        },
        core_test_template + {
                'sources' : files('test-bpf-lsm.c'),
                'dependencies' : common_test_dependencies,
        },
        core_test_template + {
                'sources' : files('test-cgroup-cpu.c'),
        },
        core_test_template + {
                'sources' : files('test-cgroup-mask.c'),
                'dependencies' : common_test_dependencies,
        },
        core_test_template + {
                'sources' : files('test-cgroup-unit-default.c'),
        },
        core_test_template + {
                'sources' : files('test-chown-rec.c'),
        },
        core_test_template + {
                'sources' : files('test-core-unit.c'),
                'dependencies' : common_test_dependencies,
        },
        core_test_template + {
                'sources' : files('test-emergency-action.c'),
        },
        core_test_template + {
                'sources' : files('test-engine.c'),
                'dependencies' : common_test_dependencies,
        },
        core_test_template + {
                'sources' : files('test-execute.c'),
                'dependencies' : common_test_dependencies,
                'timeout' : 360,
        },
        core_test_template + {
                'sources' : files('test-install.c'),
                'type' : 'manual',
        },
        core_test_template + {
                'sources' : files('test-job-type.c'),
                'dependencies' : common_test_dependencies,
        },
        core_test_template + {
                'sources' : files('test-load-fragment.c'),
                'dependencies' : common_test_dependencies,
        },
        core_test_template + {
                'sources' : files('test-loop-block.c'),
                'dependencies' : [threads, libblkid],
                'parallel' : false,
        },
        core_test_template + {
                'sources' : files('test-manager.c'),
        },
        core_test_template + {
                'sources' : files('test-namespace.c'),
                'dependencies' : [
                        libblkid,
                        threads,
                ],
        },
        core_test_template + {
                'sources' : files('test-ns.c'),
                'dependencies' : common_test_dependencies,
                'type' : 'manual',
        },
        core_test_template + {
                'sources' : files('test-path.c'),
                'dependencies' : common_test_dependencies,
                'timeout' : 120,
        },
        core_test_template + {
                'sources' : files('test-sched-prio.c'),
                'dependencies' : common_test_dependencies,
        },
        core_test_template + {
                'sources' : files('test-socket-bind.c'),
                'dependencies' : libdl,
                'conditions' : ['BPF_FRAMEWORK'],
        },
        core_test_template + {
                'sources' : files('test-tables.c'),
        },
        core_test_template + {
                'sources' : files('test-unit-name.c'),
                'dependencies' : common_test_dependencies,
        },
        core_test_template + {
                'sources' : files('test-unit-serialize.c'),
                'dependencies' : common_test_dependencies,
        },
        core_test_template + {
                'sources' : files('test-watch-pid.c'),
                'dependencies' : common_test_dependencies,
        },

        # Tests from other directories that have link_with deps that were not defined earlier
        test_template + {
                'sources' : files('../libsystemd/sd-bus/test-bus-error.c'),
                'link_with' : [
                        libshared_static,
                        libsystemd_static,
                ],
        },
        test_template + {
                'sources' : files('../libsystemd/sd-device/test-sd-device-thread.c'),
                'link_with' : libsystemd,
                'dependencies' : threads,
        },
        test_template + {
                'sources' : files('../libudev/test-udev-device-thread.c'),
                'link_with' : libudev,
                'dependencies' : threads,
        },
        test_template + {
                'sources' : files('../libudev/test-libudev.c'),
                'link_with' : [
                        libshared,
                        libudev_basic,
                ],
        },
]
