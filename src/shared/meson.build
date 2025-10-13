# SPDX-License-Identifier: LGPL-2.1-or-later

shared_sources = files(
        'acl-util.c',
        'acpi-fpdt.c',
        'apparmor-util.c',
        'ask-password-agent.c',
        'ask-password-api.c',
        'async.c',
        'barrier.c',
        'base-filesystem.c',
        'battery-util.c',
        'binfmt-util.c',
        'bitmap.c',
        'blkid-util.c',
        'blockdev-list.c',
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
        'cryptsetup-fido2.c',
        'cryptsetup-tpm2.c',
        'cryptsetup-util.c',
        'daemon-util.c',
        'data-fd-util.c',
        'dev-setup.c',
        'device-nodes.c',
        'discover-image.c',
        'dissect-image.c',
        'dm-util.c',
        'dns-domain.c',
        'dropin.c',
        'edit-util.c',
        'efi-api.c',
        'efi-loader.c',
        'elf-util.c',
        'enable-mempool.c',
        'ethtool-util.c',
        'exec-util.c',
        'exit-status.c',
        'extension-util.c',
        'factory-reset.c',
        'fdset.c',
        'fido2-util.c',
        'find-esp.c',
        'firewall-util-nft.c',
        'firewall-util.c',
        'fork-notify.c',
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
        'ioprio-util.c',
        'ip-protocol-list.c',
        'ipvlan-util.c',
        'journal-file-util.c',
        'journal-importer.c',
        'journal-util.c',
        'kbd-util.c',
        'kernel-config.c',
        'kernel-image.c',
        'killall.c',
        'label-util.c',
        'libarchive-util.c',
        'libaudit-util.c',
        'libcrypt-util.c',
        'libfido2-util.c',
        'libmount-util.c',
        'local-addresses.c',
        'locale-setup.c',
        'log-assert-critical.c',
        'logs-show.c',
        'loop-util.c',
        'loopback-setup.c',
        'lsm-util.c',
        'machine-bind-user.c',
        'machine-credential.c',
        'machine-id-setup.c',
        'machine-pool.c',
        'macvlan-util.c',
        'main-func.c',
        'mkdir-label.c',
        'mkfs-util.c',
        'module-util.c',
        'mount-setup.c',
        'mount-util.c',
        'net-condition.c',
        'netif-naming-scheme.c',
        'netif-sriov.c',
        'netif-util.c',
        'notify-recv.c',
        'nsflags.c',
        'nsresource.c',
        'numa-util.c',
        'open-file.c',
        'openssl-util.c',
        'osc-context.c',
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
        'polkit-agent.c',
        'portable-util.c',
        'pretty-print.c',
        'ptyfwd.c',
        'qrcode-util.c',
        'quota-util.c',
        'reboot-util.c',
        'recovery-key.c',
        'resize-fs.c',
        'resolve-util.c',
        'rm-rf.c',
        'seccomp-util.c',
        'securebits-util.c',
        'selinux-util.c',
        'serialize.c',
        'service-util.c',
        'shift-uid.c',
        'sleep-config.c',
        'smack-util.c',
        'smbios11.c',
        'socket-label.c',
        'socket-netlink.c',
        'specifier.c',
        'switch-root.c',
        'tmpfile-util-label.c',
        'tomoyo-util.c',
        'tpm2-util.c',
        'tpm2-event-log.c',
        'udev-util.c',
        'unit-file.c',
        'user-record-nss.c',
        'user-record-show.c',
        'user-record.c',
        'userdb-dropin.c',
        'userdb.c',
        'varlink-idl-common.c',
        'varlink-io.systemd.AskPassword.c',
        'varlink-io.systemd.BootControl.c',
        'varlink-io.systemd.Credentials.c',
        'varlink-io.systemd.FactoryReset.c',
        'varlink-io.systemd.Hostname.c',
        'varlink-io.systemd.Import.c',
        'varlink-io.systemd.Journal.c',
        'varlink-io.systemd.Login.c',
        'varlink-io.systemd.Machine.c',
        'varlink-io.systemd.MachineImage.c',
        'varlink-io.systemd.ManagedOOM.c',
        'varlink-io.systemd.Manager.c',
        'varlink-io.systemd.MountFileSystem.c',
        'varlink-io.systemd.NamespaceResource.c',
        'varlink-io.systemd.Network.c',
        'varlink-io.systemd.PCRExtend.c',
        'varlink-io.systemd.PCRLock.c',
        'varlink-io.systemd.Resolve.c',
        'varlink-io.systemd.Resolve.Monitor.c',
        'varlink-io.systemd.Udev.c',
        'varlink-io.systemd.Unit.c',
        'varlink-io.systemd.UserDatabase.c',
        'varlink-io.systemd.oom.c',
        'varlink-io.systemd.service.c',
        'varlink-io.systemd.sysext.c',
        'varlink-serialize.c',
        'vconsole-util.c',
        'verb-log-control.c',
        'verbs.c',
        'vlan-util.c',
        'volatile-util.c',
        'vpick.c',
        'wall.c',
        'watchdog.c',
        'web-util.c',
        'wifi-util.c',
        'xml.c',
)

if conf.get('ENABLE_NSS') == 1
        shared_sources += files('nss-util.c')
endif

if get_option('tests') != 'false'
        shared_sources += files('tests.c')
endif

syscall_list_inc = custom_target(
        input : syscall_list_txt,
        output : 'syscall-list.inc',
        command : [files('generate-syscall-list.py'),
                   '@INPUT@'],
        capture : true)

generated_sources += syscall_list_inc
shared_sources += syscall_list_inc

if conf.get('ENABLE_UTMP') == 1
        shared_sources += files('utmp-wtmp.c')
endif

if conf.get('HAVE_LIBIPTC') == 1
        shared_sources += files('firewall-util-iptables.c')
endif

if conf.get('HAVE_LIBBPF') == 1
        shared_sources += files('bpf-link.c')
endif

if conf.get('HAVE_PAM') == 1
        shared_sources += files('pam-util.c')
endif

generate_ip_protocol_list = files('generate-ip-protocol-list.sh')
ip_protocol_list_txt = custom_target(
        input : [generate_ip_protocol_list, ipproto_sources],
        output : 'ip-protocol-list.txt',
        command : [env, 'bash', generate_ip_protocol_list, cpp, system_include_args],
        capture : true)

gperf_file = custom_target(
        input : ip_protocol_list_txt,
        output : 'ip-protocol-from-name.gperf',
        command : [generate_gperfs, 'ip_protocol', 'IPPROTO_', '@INPUT@', '<netinet/in.h>'],
        capture : true)

target1 = custom_target(
        input : gperf_file,
        output : 'ip-protocol-from-name.inc',
        command : [gperf,
                   '-L', 'ANSI-C', '-t', '--ignore-case',
                   '-N', 'lookup_ip_protocol',
                   '-H', 'hash_ip_protocol_name',
                   '-p', '-C',
                   '@INPUT@'],
        capture : true)

awkscript = 'ip-protocol-to-name.awk'
target2 = custom_target(
        input : [awkscript, ip_protocol_list_txt],
        output : 'ip-protocol-to-name.inc',
        command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
        capture : true)

generated_sources += [target1, target2]
shared_sources += [target1, target2]

ethtool_link_mode_py = files('ethtool-link-mode.py')
ethtool_link_mode_inc = custom_target(
        input : [ethtool_link_mode_py, ethtool_link_mode_sources],
        output : 'ethtool-link-mode.inc',
        command : [python, ethtool_link_mode_py, '--header', cpp, system_include_args],
        capture : true)

generated_sources += ethtool_link_mode_inc
shared_sources += ethtool_link_mode_inc
sources += shared_sources

ethtool_link_mode_xml = custom_target(
        input : [ethtool_link_mode_py, ethtool_link_mode_sources],
        output : 'ethtool-link-mode.xml',
        command : [python, ethtool_link_mode_py, '--xml', cpp, system_include_args],
        capture : true)
man_page_depends += ethtool_link_mode_xml

libshared_name = 'systemd-shared-@0@'.format(shared_lib_tag)

libshared_deps = [threads,
                  libacl,
                  libaudit,
                  libblkid,
                  libcap,
                  libcrypt,
                  libdl,
                  libgcrypt,
                  libiptc_cflags,
                  libkmod_cflags,
                  liblz4_cflags,
                  libmount,
                  libopenssl,
                  libp11kit_cflags,
                  libpam,
                  librt,
                  libseccomp,
                  libselinux,
                  libxenctrl_cflags,
                  libxz_cflags,
                  libzstd_cflags]

libshared_sym_path = meson.current_source_dir() / 'libshared.sym'
libshared_build_dir = meson.current_build_dir()

libshared_static = static_library(
        libshared_name,
        shared_sources,
        include_directories : includes,
        implicit_include_directories : false,
        dependencies : [libshared_deps,
                        userspace],
        c_args : ['-fvisibility=default'],
        build_by_default : false)

libshared = shared_library(
        libshared_name,
        include_directories : includes,
        implicit_include_directories : false,
        c_args : ['-fvisibility=default'],
        link_args : ['-shared',
                     '-Wl,--version-script=' + libshared_sym_path],
        link_depends : libshared_sym_path,
        link_whole : [libc_wrapper_static,
                      libshared_static,
                      libbasic_static,
                      libsystemd_static],
        dependencies : [libshared_deps,
                        userspace],
        install : true,
        install_dir : pkglibdir)

shared_fdisk_sources = files('fdisk-util.c')

libshared_fdisk = static_library(
        'shared-fdisk',
        shared_fdisk_sources,
        include_directories : includes,
        implicit_include_directories : false,
        dependencies : [libfdisk,
                        userspace],
        c_args : ['-fvisibility=default'],
        build_by_default : false)
