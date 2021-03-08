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

path = run_command('sh', ['-c', 'echo "$PATH"']).stdout().strip()
test_env = environment()
test_env.set('SYSTEMD_KBD_MODEL_MAP', kbd_model_map)
test_env.set('SYSTEMD_LANGUAGE_FALLBACK_MAP', language_fallback_map)
test_env.set('PATH', '@0@:@1@'.format(meson.build_root(), path))

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
        [['src/test/test-device-nodes.c']],

        [['src/test/test-engine.c'],
         [libcore,
          libshared],
         [threads,
          librt,
          libseccomp,
          libselinux,
          libmount,
          libblkid],
         core_includes],

        [['src/test/test-emergency-action.c'],
         [libcore,
          libshared],
         [],
         core_includes],

        [['src/test/test-chown-rec.c'],
         [libcore,
          libshared],
         [],
         core_includes],

        [['src/test/test-dlopen-so.c']],

        [['src/test/test-job-type.c'],
         [libcore,
          libshared],
         [threads,
          librt,
          libseccomp,
          libselinux,
          libmount,
          libblkid],
         core_includes],

        [['src/test/test-ns.c'],
         [libcore,
          libshared],
         [threads,
          librt,
          libseccomp,
          libselinux,
          libmount,
          libblkid],
         core_includes, '', 'manual'],

        [['src/test/test-loopback.c'],
         [libcore,
          libshared],
         [threads,
          librt,
          libseccomp,
          libselinux,
          libmount,
          libblkid],
         core_includes],

        [['src/test/test-dns-domain.c']],

        [['src/test/test-boot-timestamps.c'],
         [], [], [], 'ENABLE_EFI'],

        [['src/test/test-unit-file.c']],

        [['src/test/test-unit-name.c'],
         [libcore,
          libshared],
         [threads,
          librt,
          libseccomp,
          libselinux,
          libmount,
          libblkid],
         core_includes],

        [['src/test/test-load-fragment.c'],
         [libcore,
          libshared],
         [threads,
          librt,
          libseccomp,
          libselinux,
          libmount,
          libblkid],
         core_includes],

        [['src/test/test-serialize.c']],

        [['src/test/test-utf8.c']],

        [['src/test/test-dev-setup.c']],

        [['src/test/test-capability.c'],
         [],
         [libcap]],

        [['src/test/test-async.c'],
         [], [], [], '', 'timeout=120'],

        [['src/test/test-locale-util.c']],

        [['src/test/test-copy.c']],

        [['src/test/test-static-destruct.c']],

        [['src/test/test-sigbus.c']],

        [['src/test/test-condition.c']],

        [['src/test/test-fdset.c']],

        [['src/test/test-fstab-util.c']],

        [['src/test/test-random-util.c']],

        [['src/test/test-format-table.c']],

        [['src/test/test-format-util.c']],

        [['src/test/test-ratelimit.c']],

        [['src/test/test-util.c']],

        [['src/test/test-json.c']],

        [['src/test/test-modhex.c']],

        [['src/test/test-libmount.c'],
         [],
         [threads,
          libmount]],

        [['src/test/test-mount-util.c']],

        [['src/test/test-mountpoint-util.c']],

        [['src/test/test-exec-util.c']],

        [['src/test/test-hexdecoct.c']],

        [['src/test/test-alloc-util.c']],

        [['src/test/test-xattr-util.c']],

        [['src/test/test-io-util.c']],

        [['src/test/test-glob-util.c']],

        [['src/test/test-fs-util.c']],

        [['src/test/test-umask-util.c']],

        [['src/test/test-proc-cmdline.c']],

        [['src/test/test-fd-util.c']],

        [['src/test/test-web-util.c']],

        [['src/test/test-cpu-set-util.c']],

        [['src/test/test-stat-util.c']],

        [['src/test/test-os-util.c']],

        [['src/test/test-libcrypt-util.c'],
         [], [], [], '', 'timeout=120'],

        [['src/test/test-escape.c']],

        [['src/test/test-exit-status.c']],

        [['src/test/test-specifier.c']],

        [['src/test/test-string-util.c']],

        [['src/test/test-extract-word.c']],

        [['src/test/test-parse-argument.c']],

        [['src/test/test-parse-util.c']],

        [['src/test/test-sysctl-util.c']],

        [['src/test/test-user-record.c']],

        [['src/test/test-user-util.c']],

        [['src/test/test-hostname-setup.c']],

        [['src/test/test-hostname-util.c']],

        [['src/test/test-process-util.c']],

        [['src/test/test-terminal-util.c']],

        [['src/test/test-path-lookup.c']],

        [['src/test/test-pretty-print.c']],

        [['src/test/test-uid-range.c']],

        [['src/test/test-cap-list.c',
          generated_gperf_headers],
         [],
         [libcap]],

        [['src/test/test-socket-util.c']],

        [['src/test/test-socket-netlink.c']],

        [['src/test/test-in-addr-util.c']],

        [['src/test/test-barrier.c']],

        [['src/test/test-tmpfiles.c']],

        [['src/test/test-namespace.c'],
         [libcore,
          libshared],
         [threads,
          libblkid],
         core_includes],

        [['src/test/test-verbs.c']],

        [['src/test/test-install-root.c']],

        [['src/test/test-acl-util.c'],
         [], [], [], 'HAVE_ACL'],

        [['src/test/test-seccomp.c'],
         [],
         [libseccomp],
         [], 'HAVE_SECCOMP'],

        [['src/test/test-rlimit-util.c']],

        [['src/test/test-ask-password-api.c'],
         [], [], [], '', 'manual'],

        [['src/test/test-signal-util.c']],

        [['src/test/test-loop-block.c'],
         [libcore,
          libshared],
         [threads,
          libblkid],
         core_includes, '', '', [], false],

        [['src/test/test-selinux.c']],

        [['src/test/test-sizeof.c'],
         [libbasic]],

        [['src/test/test-bpf-devices.c'],
         [libcore,
          libshared],
         [libmount,
          threads,
          librt,
          libseccomp,
          libselinux,
          libblkid],
         core_includes],

        [['src/test/test-bpf-firewall.c'],
         [libcore,
          libshared],
         [libmount,
          threads,
          librt,
          libseccomp,
          libselinux,
          libblkid],
         core_includes],

        [['src/test/test-watch-pid.c'],
         [libcore,
          libshared],
         [libmount,
          threads,
          librt,
          libseccomp,
          libselinux,
          libblkid],
         core_includes],

        [['src/test/test-hashmap.c',
          'src/test/test-hashmap-plain.c',
          test_hashmap_ordered_c],
         [], [], [], '', 'timeout=90'],

        [['src/test/test-set.c'],
         [libbasic]],

        [['src/test/test-ordered-set.c']],

        [['src/test/test-set-disable-mempool.c'],
         [],
         [threads]],

        [['src/test/test-bitmap.c']],

        [['src/test/test-xml.c']],

        [['src/test/test-list.c']],

        [['src/test/test-procfs-util.c']],

        [['src/test/test-unaligned.c']],

        [['src/test/test-tables.c'],
         [libcore,
          libjournal_core,
          libudevd_core,
          libshared],
         [threads,
          libseccomp,
          libmount,
          libxz,
          liblz4,
          libblkid],
         [core_includes, journal_includes, udev_includes]],

        [['src/test/test-prioq.c']],

        [['src/test/test-fileio.c']],

        [['src/test/test-time-util.c']],

        [['src/test/test-clock.c']],

        [['src/test/test-tmpfile-util.c']],

        [['src/test/test-architecture.c']],

        [['src/test/test-log.c']],

        [['src/test/test-ipcrm.c'],
         [], [], [], '', 'unsafe'],

        [['src/test/test-btrfs.c'],
         [], [], [], '', 'manual'],

        [['src/test/test-firewall-util.c']],

        [['src/test/test-netlink-manual.c'],
         [],
         [libkmod],
         [], 'HAVE_KMOD', 'manual'],

        [['src/test/test-ellipsize.c']],

        [['src/test/test-date.c']],

        [['src/test/test-sleep.c']],

        [['src/test/test-replace-var.c']],

        [['src/test/test-calendarspec.c']],

        [['src/test/test-strip-tab-ansi.c']],

        [['src/test/test-coredump-util.c']],

        [['src/test/test-daemon.c']],

        [['src/test/test-cgroup.c']],

        [['src/test/test-cgroup-cpu.c'],
         [libcore,
          libshared],
         [],
         core_includes],

        [['src/test/test-cgroup-unit-default.c'],
         [libcore,
          libshared],
         [],
         core_includes],

        [['src/test/test-cgroup-mask.c'],
         [libcore,
          libshared],
         [threads,
          librt,
          libseccomp,
          libselinux,
          libmount,
          libblkid],
         core_includes],

        [['src/test/test-varlink.c'],
         [],
         [threads]],

        [['src/test/test-cgroup-util.c']],

        [['src/test/test-cgroup-setup.c']],

        [['src/test/test-env-file.c']],

        [['src/test/test-env-util.c']],

        [['src/test/test-strbuf.c']],

        [['src/test/test-strv.c']],

        [['src/test/test-path-util.c']],

        [['src/test/test-rm-rf.c']],

        [['src/test/test-chase-symlinks.c'],
         [], [], [], '', 'manual'],

        [['src/test/test-path.c'],
         [libcore,
          libshared],
         [threads,
          librt,
          libseccomp,
          libselinux,
          libmount,
          libblkid],
         core_includes, '', 'timeout=120'],

        [['src/test/test-execute.c'],
         [libcore,
          libshared],
         [threads,
          librt,
          libseccomp,
          libselinux,
          libmount,
          libblkid],
         core_includes, '', 'timeout=360'],

        [['src/test/test-siphash24.c']],

        [['src/test/test-strxcpyx.c']],

        [['src/test/test-install.c'],
         [libcore,
          libshared],
         [],
         core_includes, '', 'manual'],

        [['src/test/test-watchdog.c']],

        [['src/test/test-sched-prio.c'],
         [libcore,
          libshared],
         [threads,
          librt,
          libseccomp,
          libselinux,
          libmount,
          libblkid],
         core_includes],

        [['src/test/test-conf-files.c']],

        [['src/test/test-conf-parser.c']],

        [['src/test/test-af-list.c',
          generated_gperf_headers]],

        [['src/test/test-arphrd-list.c',
          generated_gperf_headers]],

        [['src/test/test-ip-protocol-list.c',
          shared_generated_gperf_headers]],

        [['src/test/test-journal-importer.c']],

        [['src/test/test-udev.c'],
         [libudevd_core,
          libshared],
         [threads,
          librt,
          libblkid,
          libkmod,
          libacl,
          libselinux],
         udev_includes, '', 'manual'],

        [['src/test/test-udev-util.c']],

        [['src/test/test-id128.c']],

        [['src/test/test-hash.c']],

        [['src/test/test-gcrypt-util.c'],
         [], [], [], 'HAVE_GCRYPT'],

        [['src/test/test-nss.c'],
         [],
         [libdl],
         [], 'ENABLE_NSS', 'manual'],

        [['src/test/test-bus-util.c']],

        [['src/test/test-percent-util.c']],

        [['src/test/test-sd-hwdb.c']],

        [['src/test/test-sd-path.c']],

        [['src/test/test-local-addresses.c']],

        [['src/test/test-psi-util.c']],

        [['src/test/test-qrcode-util.c'],
         [],
         [libdl]],

        [['src/test/test-nscd-flush.c'],
         [], [], [], 'ENABLE_NSCD', 'manual'],
]

############################################################

# define some tests here, because the link_with deps were not defined earlier

tests += [
        [['src/libsystemd/sd-bus/test-bus-error.c'],
         [libshared_static,
          libsystemd_static]],

        [['src/libsystemd/sd-device/test-sd-device-thread.c'],
         [libsystemd],
         [threads]],

        [['src/libudev/test-udev-device-thread.c'],
         [libudev],
         [threads]],
]
