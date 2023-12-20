# SPDX-License-Identifier: LGPL-2.1-or-later

shared_sources = files(
        'acl-util.c',
        'acpi-fpdt.c',
        'apparmor-util.c',
        'ask-password-api.c',
        'async.c',
        'barrier.c',
        'base-filesystem.c',
        'battery-util.c',
        'binfmt-util.c',
        'bitmap.c',
        'blockdev-util.c',
        'bond-util.c',
        'boot-entry.c',
        'boot-timestamps.c',
        'bootspec.c',
        'bpf-dlopen.c',
        'bpf-program.c',
        'bridge-util.c',
        'btrfs-util.c',
        'bus-get-properties.c',
        'bus-locator.c',
        'bus-log-control-api.c',
        'bus-map-properties.c',
        'bus-message-util.c',
        'bus-object.c',
        'bus-polkit.c',
        'bus-print-properties.c',
        'bus-unit-procs.c',
        'bus-unit-util.c',
        'bus-util.c',
        'bus-wait-for-jobs.c',
        'bus-wait-for-units.c',
        'calendarspec.c',
        'cgroup-setup.c',
        'cgroup-show.c',
        'chown-recursive.c',
        'clean-ipc.c',
        'clock-util.c',
        'color-util.c',
        'common-signal.c',
        'compare-operator.c',
        'condition.c',
        'conf-parser.c',
        'copy.c',
        'coredump-util.c',
        'cpu-set-util.c',
        'creds-util.c',
        'cryptsetup-util.c',
        'daemon-util.c',
        'data-fd-util.c',
        'dev-setup.c',
        'device-nodes.c',
        'discover-image.c',
        'dissect-image.c',
        'dlfcn-util.c',
        'dm-util.c',
        'dns-domain.c',
        'dropin.c',
        'edit-util.c',
        'efi-api.c',
        'efi-loader.c',
        'elf-util.c',
        'enable-mempool.c',
        'env-file-label.c',
        'ethtool-util.c',
        'exec-util.c',
        'exit-status.c',
        'extension-util.c',
        'fdset.c',
        'fileio-label.c',
        'find-esp.c',
        'firewall-util-nft.c',
        'firewall-util.c',
        'format-table.c',
        'fstab-util.c',
        'generator.c',
        'geneve-util.c',
        'gpt.c',
        'group-record.c',
        'hibernate-util.c',
        'hostname-setup.c',
        'hwdb-util.c',
        'id128-print.c',
        'idn-util.c',
        'ima-util.c',
        'image-policy.c',
        'import-util.c',
        'in-addr-prefix-util.c',
        'install-file.c',
        'install-printf.c',
        'install.c',
        'ip-protocol-list.c',
        'ipvlan-util.c',
        'journal-file-util.c',
        'journal-importer.c',
        'journal-util.c',
        'json.c',
        'kbd-util.c',
        'kernel-image.c',
        'keyring-util.c',
        'killall.c',
        'label-util.c',
        'libcrypt-util.c',
        'libfido2-util.c',
        'libmount-util.c',
        'local-addresses.c',
        'locale-setup.c',
        'logs-show.c',
        'loop-util.c',
        'loopback-setup.c',
        'lsm-util.c',
        'machine-credential.c',
        'machine-id-setup.c',
        'machine-pool.c',
        'macvlan-util.c',
        'mkdir-label.c',
        'mkfs-util.c',
        'mount-setup.c',
        'mount-util.c',
        'net-condition.c',
        'netif-naming-scheme.c',
        'netif-sriov.c',
        'netif-util.c',
        'nsflags.c',
        'numa-util.c',
        'open-file.c',
        'openssl-util.c',
        'output-mode.c',
        'pager.c',
        'parse-argument.c',
        'parse-helpers.c',
        'password-quality-util-passwdqc.c',
        'password-quality-util-pwquality.c',
        'pcre2-util.c',
        'pcrextend-util.c',
        'pe-binary.c',
        'pkcs11-util.c',
        'plymouth-util.c',
        'pretty-print.c',
        'ptyfwd.c',
        'qrcode-util.c',
        'quota-util.c',
        'reboot-util.c',
        'recovery-key.c',
        'resize-fs.c',
        'resolve-util.c',
        'rm-rf.c',
        'securebits-util.c',
        'selinux-util.c',
        'serialize.c',
        'service-util.c',
        'sleep-config.c',
        'smack-util.c',
        'socket-label.c',
        'socket-netlink.c',
        'spawn-ask-password-agent.c',
        'spawn-polkit-agent.c',
        'specifier.c',
        'switch-root.c',
        'tmpfile-util-label.c',
        'tomoyo-util.c',
        'tpm2-util.c',
        'tpm2-event-log.c',
        'udev-util.c',
        'user-record-nss.c',
        'user-record-show.c',
        'user-record.c',
        'userdb-dropin.c',
        'userdb.c',
        'varlink.c',
        'varlink-idl.c',
        'varlink-io.systemd.c',
        'varlink-io.systemd.Journal.c',
        'varlink-io.systemd.ManagedOOM.c',
        'varlink-io.systemd.PCRExtend.c',
        'varlink-io.systemd.Resolve.Monitor.c',
        'varlink-io.systemd.Resolve.c',
        'varlink-io.systemd.UserDatabase.c',
        'varlink-io.systemd.oom.c',
        'varlink-io.systemd.service.c',
        'varlink-io.systemd.sysext.c',
        'varlink-org.varlink.service.c',
        'verb-log-control.c',
        'verbs.c',
        'vlan-util.c',
        'volatile-util.c',
        'wall.c',
        'watchdog.c',
        'web-util.c',
        'wifi-util.c',
        'xml.c',
)

if get_option('tests') != 'false'
        shared_sources += files(
                'tests.c',
        )
endif

generate_syscall_list = find_program('generate-syscall-list.py')
fname = 'syscall-list.h'
syscall_list_h = custom_target(
        fname,
        input : syscall_list_txt,
        output : fname,
        command : [generate_syscall_list,
                   '@INPUT@'],
        capture : true)

if conf.get('HAVE_ACL') == 1
        shared_sources += files(
                'devnode-acl.c',
        )
endif

if conf.get('ENABLE_UTMP') == 1
        shared_sources += files('utmp-wtmp.c')
endif

if conf.get('HAVE_SECCOMP') == 1
        shared_sources += files('seccomp-util.c')
        shared_sources += syscall_list_h
endif

if conf.get('HAVE_LIBIPTC') == 1
        shared_sources += files('firewall-util-iptables.c')
endif

if conf.get('HAVE_LIBBPF') == 1
        shared_sources += files(
                'bpf-link.c',
        )
endif

if conf.get('HAVE_KMOD') == 1
        shared_sources += files('module-util.c')
endif

if conf.get('HAVE_PAM') == 1
        shared_sources += files(
                'pam-util.c',
        )
endif

if conf.get('ENABLE_NSCD') == 1
        shared_sources += files('nscd-flush.c')
endif

if conf.get('HAVE_LIBFIDO2') == 1 and conf.get('HAVE_LIBCRYPTSETUP') == 1
        shared_sources += files('cryptsetup-fido2.c')
endif

generate_ip_protocol_list = find_program('generate-ip-protocol-list.sh')
ip_protocol_list_txt = custom_target(
        'ip-protocol-list.txt',
        output : 'ip-protocol-list.txt',
        command : [generate_ip_protocol_list, cpp],
        capture : true)

fname = 'ip-protocol-from-name.gperf'
gperf_file = custom_target(
        fname,
        input : ip_protocol_list_txt,
        output : fname,
        command : [generate_gperfs, 'ip_protocol', 'IPPROTO_', '@INPUT@'],
        capture : true)

fname = 'ip-protocol-from-name.h'
target1 = custom_target(
        fname,
        input : gperf_file,
        output : fname,
        command : [gperf,
                   '-L', 'ANSI-C', '-t', '--ignore-case',
                   '-N', 'lookup_ip_protocol',
                   '-H', 'hash_ip_protocol_name',
                   '-p', '-C',
                   '@INPUT@'],
        capture : true)

fname = 'ip-protocol-to-name.h'
awkscript = 'ip-protocol-to-name.awk'
target2 = custom_target(
        fname,
        input : [awkscript, ip_protocol_list_txt],
        output : fname,
        command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
        capture : true)

shared_generated_gperf_headers = [target1, target2]
shared_sources += shared_generated_gperf_headers

fname = 'ethtool-link-mode.h'
ethtool_link_mode_h = custom_target(
        fname,
        input : ['ethtool-link-mode.py', 'linux/ethtool.h'],
        output : fname,
        command : [python, '@INPUT0@', '--header', cpp, '@INPUT1@'],
        capture : true)
shared_sources += ethtool_link_mode_h

fname = 'ethtool-link-mode.xml'
ethtool_link_mode_xml = custom_target(
        fname,
        input : ['ethtool-link-mode.py', 'linux/ethtool.h'],
        output : fname,
        command : [python, '@INPUT0@', '--xml', cpp, '@INPUT1@'],
        capture : true)
man_page_depends += ethtool_link_mode_xml

libshared_name = 'systemd-shared-@0@'.format(shared_lib_tag)

libshared_deps = [threads,
                  libacl,
                  libblkid,
                  libcap,
                  libcrypt,
                  libdl,
                  libgcrypt,
                  libiptc_cflags,
                  libkmod,
                  liblz4,
                  libmount,
                  libopenssl,
                  libp11kit_cflags,
                  libpam,
                  librt,
                  libseccomp,
                  libselinux,
                  libxenctrl_cflags,
                  libxz,
                  libzstd]

libshared_sym_path = meson.current_source_dir() / 'libshared.sym'
libshared_build_dir = meson.current_build_dir()

libshared_static = static_library(
        libshared_name,
        shared_sources,
        include_directories : includes,
        dependencies : [libshared_deps,
                        userspace],
        c_args : ['-fvisibility=default'],
        build_by_default : false)

libshared = shared_library(
        libshared_name,
        include_directories : includes,
        c_args : ['-fvisibility=default'],
        link_args : ['-shared',
                     '-Wl,--version-script=' + libshared_sym_path],
        link_depends : libshared_sym_path,
        link_whole : [libshared_static,
                      libbasic,
                      libbasic_gcrypt,
                      libsystemd_static],
        dependencies : [libshared_deps,
                        userspace],
        install : true,
        install_dir : pkglibdir)

shared_fdisk_sources = files(
        'fdisk-util.c',
)

libshared_fdisk = static_library(
        'shared-fdisk',
        shared_fdisk_sources,
        include_directories : includes,
        dependencies : [libfdisk,
                        userspace],
        c_args : ['-fvisibility=default'],
        build_by_default : false)
