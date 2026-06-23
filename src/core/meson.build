# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_sources = files(
        'apparmor-setup.c',
        'clock-warp.c',
        'crash-handler.c',
        'efi-random.c',
        'ima-setup.c',
        'import-creds.c',
        'ipe-setup.c',
        'kmod-setup.c',
        'main.c',
        'smack-setup.c',
)

if conf.get('HAVE_SELINUX') == 1
        systemd_sources += files('selinux-setup.c')
endif

systemd_executor_sources = files(
        'executor.c',
        'exec-invoke.c',
)

libcore_sources = files(
        'audit-fd.c',
        'automount.c',
        'bpf-bind-iface.c',
        'bpf-devices.c',
        'bpf-firewall.c',
        'bpf-foreign.c',
        'bpf-restrict-fs.c',
        'bpf-restrict-fsaccess.c',
        'bpf-restrict-ifaces.c',
        'bpf-socket-bind.c',
        'cgroup.c',
        'dbus-automount.c',
        'dbus-cgroup.c',
        'dbus-device.c',
        'dbus-execute.c',
        'dbus-job.c',
        'dbus-kill.c',
        'dbus-manager.c',
        'dbus-mount.c',
        'dbus-path.c',
        'dbus-scope.c',
        'dbus-service.c',
        'dbus-slice.c',
        'dbus-socket.c',
        'dbus-swap.c',
        'dbus-target.c',
        'dbus-timer.c',
        'dbus-unit.c',
        'dbus-util.c',
        'dbus.c',
        'device.c',
        'dynamic-user.c',
        'emergency-action.c',
        'exec-credential.c',
        'execute.c',
        'execute-serialize.c',
        'generator-setup.c',
        'job.c',
        'kill.c',
        'load-dropin.c',
        'load-fragment.c',
        'luo.c',
        'manager-dump.c',
        'manager-serialize.c',
        'manager.c',
        'mount.c',
        'namespace.c',
        'path.c',
        'scope.c',
        'selinux-access.c',
        'service.c',
        'show-status.c',
        'slice.c',
        'socket.c',
        'swap.c',
        'taint.c',
        'target.c',
        'timer.c',
        'transaction.c',
        'unit-dependency-atom.c',
        'unit-printf.c',
        'unit-serialize.c',
        'unit.c',
        'varlink.c',
        'varlink-automount.c',
        'varlink-cgroup.c',
        'varlink-common.c',
        'varlink-dynamic-user.c',
        'varlink-execute.c',
        'varlink-job.c',
        'varlink-kill.c',
        'varlink-manager.c',
        'varlink-metrics.c',
        'varlink-mount.c',
        'varlink-path.c',
        'varlink-scope.c',
        'varlink-service.c',
        'varlink-socket.c',
        'varlink-swap.c',
        'varlink-timer.c',
        'varlink-unit.c',
)

if conf.get('BPF_FRAMEWORK') == 1
        foreach name : ['socket-bind', 'restrict-fs', 'restrict-ifaces', 'bind-iface']
                libcore_sources += bpf_programs_by_name[name]
        endforeach
endif

if conf.get('HAVE_LSM_INTEGRITY_TYPE') == 1
        libcore_sources += bpf_programs_by_name['restrict-fsaccess']
endif

sources += libcore_sources

shutdown_detach_sources = files(
        'detach-swap.c',
        'umount.c',
)

systemd_shutdown_sources = files(
        'detach-dm.c',
        'detach-loopback.c',
        'detach-md.c',
        'shutdown.c',
)

if conf.get('HAVE_LIBMOUNT') == 1
        systemd_shutdown_sources += shutdown_detach_sources
endif

load_fragment_gperf_gperf = custom_target(
        input : 'load-fragment-gperf.gperf.in',
        output: 'load-fragment-gperf.gperf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'])

load_fragment_gperf_c = custom_target(
        input : load_fragment_gperf_gperf,
        output : 'load-fragment-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

awkscript = 'load-fragment-gperf-nulstr.awk'
load_fragment_gperf_nulstr_c = custom_target(
        input : [awkscript, load_fragment_gperf_gperf],
        output : 'load-fragment-gperf-nulstr.c',
        command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
        capture : true)

generate_bpf_delegate_configs = files('generate-bpf-delegate-configs.py')
bpf_delegate_configs_inc = custom_target(
        input : [generate_bpf_delegate_configs, bpf_delegate_sources],
        output : 'bpf-delegate-configs.inc',
        command : [python,
                   generate_bpf_delegate_configs,
                   'code',
                   bpf_delegate_sources],
        capture : true)

bpf_delegate_xml = custom_target(
        input : [generate_bpf_delegate_configs, bpf_delegate_sources],
        output : 'bpf-delegate.xml',
        command : [python,
                   generate_bpf_delegate_configs,
                   'doc',
                   bpf_delegate_sources],
        capture : true)
man_page_depends += bpf_delegate_xml

generated_sources += [load_fragment_gperf_c, load_fragment_gperf_nulstr_c, bpf_delegate_configs_inc]
libcore_sources += [load_fragment_gperf_c, load_fragment_gperf_nulstr_c, bpf_delegate_configs_inc]
libcore_build_dir = meson.current_build_dir()
libcore_name = 'systemd-core-@0@'.format(shared_lib_tag)
core_includes = [include_directories('.'), includes]

libcore_static = static_library(
        libcore_name,
        libcore_sources,
        include_directories : core_includes,
        implicit_include_directories : false,
        c_args : ['-fvisibility=default'],
        dependencies : [libaudit_cflags,
                        libbpf_cflags,
                        libcryptsetup_cflags,
                        libm,
                        libmount_cflags,
                        libseccomp_cflags,
                        libselinux_cflags,
                        userspace],
        build_by_default : false)

libcore = shared_library(
        libcore_name,
        c_args : ['-fvisibility=default'],
        implicit_include_directories : false,
        link_args : ['-shared',
                     '-Wl,--version-script=' + libshared_sym_path],
        link_depends : libshared_sym_path,
        link_whole: libcore_static,
        link_with : libshared,
        install : true,
        install_dir : pkglibdir)

core_libs_static = [
        libc_wrapper_static,
        libcore_static,
        libshared_static,
        libbasic_static,
        libsystemd_static,
]
core_libs_shared = [
        libcore,
        libshared,
]

systemd_deps = [
        libapparmor_cflags,
        libkmod_cflags,
        libmount_cflags,
        libseccomp_cflags,
        libselinux_cflags,
]


systemd_link_args = get_option('build-static') ? ['-static'] : []
systemd_libs = get_option('build-static') ? core_libs_static : core_libs_shared

executor_libs = get_option('link-executor-shared') ? core_libs_shared : core_libs_static

if conf.get('SYSTEMD_MULTICALL_BINARY') == 1
        systemd_sources += systemd_executor_sources
        systemd_deps += [
                libbpf_cflags,
                libcryptsetup_cflags,
                libpam_cflags,
        ]
endif

executables += [
        libexec_template + {
                'name' : 'systemd',
                'dbus' : true,
                'public' : true,
                'sources' : systemd_sources,
                'link_args' : systemd_link_args,
                'link_with' : systemd_libs,
                'dependencies' : systemd_deps,
        },

        libexec_template + {
                'name' : 'systemd-executor',
                'public' : true,
                'sources' : systemd_executor_sources,
                'link_with' : executor_libs,
                'dependencies' : [
                        libapparmor_cflags,
                        libbpf_cflags,
                        libcryptsetup_cflags,
                        libmount_cflags,
                        libpam_cflags,
                        libseccomp_cflags,
                        libselinux_cflags,
                ],
                'conditions' : [conf.get('SYSTEMD_MULTICALL_BINARY') == 0],
        },

        libexec_template + {
                'name' : 'systemd-shutdown',
                'extract' : systemd_shutdown_sources,
                'dependencies' : libmount_cflags,
        },
        libexec_template + {
                'name' : 'systemd-shutdown.standalone',
                'objects' : ['systemd-shutdown'],
                'link_with' : [
                        libc_wrapper_static,
                        libbasic_static,
                        libshared_static,
                        libsystemd_static,
                ],
                'dependencies' : libmount_cflags,
        },

        test_template + {
                'sources' : files('test-umount.c') +
                            shutdown_detach_sources,
                'dependencies' : libmount_cflags,
                'conditions' : ['HAVE_LIBMOUNT'],
        },

        fuzz_template + {
                'sources' : files('fuzz-unit-file.c'),
                'link_with' : [
                        libcore,
                        libshared
                ],
                'dependencies' : libmount_cflags,
        },
        fuzz_template + {
                'sources' : files('fuzz-manager-serialize.c'),
                'link_with' : [
                        libcore,
                        libshared
                ],
        },
        fuzz_template + {
                'sources' : files('fuzz-execute-serialize.c'),
                'link_with' : [
                        libcore,
                        libshared
                ],
        },
]

if conf.get('SYSTEMD_MULTICALL_BINARY') == 1
        # Symlink for external callers
        install_symlink('systemd-executor',
                        pointing_to : 'systemd',
                        install_dir : libexecdir)
endif

in_files = [['system.conf',                     pkgconfigfiledir],
            ['user.conf',                       pkgconfigfiledir],
            ['org.freedesktop.systemd1.policy', polkitpolicydir]]

foreach item : in_files
        file = item[0]
        dir = item[1]

        custom_target(
                input : file + '.in',
                output: file,
                command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                install : (dir == pkgconfigfiledir) ? install_sysconfdir_samples : (dir != 'no'),
                install_dir : dir)
endforeach

systemd_pc = custom_target(
        input : 'systemd.pc.in',
        output : 'systemd.pc',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : pkgconfigdatadir != 'no',
        install_tag : 'devel',
        install_dir : pkgconfigdatadir)

install_data('org.freedesktop.systemd1.conf',
             install_dir : dbuspolicydir)
install_data('org.freedesktop.systemd1.service',
             install_dir : dbussystemservicedir)

install_emptydir(systemenvgeneratordir)
install_emptydir(systemshutdowndir)
install_emptydir(systemsleepdir)
install_emptydir(systemgeneratordir)
install_emptydir(userenvgeneratordir)
install_emptydir(usergeneratordir)

if install_sysconfdir
        install_emptydir(pkgsysconfdir / 'system')
        install_emptydir(pkgsysconfdir / 'user')

        assert(sysconfdir / 'systemd' == pkgsysconfdir)
        install_symlink('user',
                        pointing_to : '../../systemd/user',
                        install_dir : sysconfdir / 'xdg/systemd')
endif

assert(fs.parent(sbindir) / 'lib/systemd' == libexecdir)
install_symlink('init',
                pointing_to : '../lib/systemd/systemd',
                install_dir : sbindir)

############################################################

core_test_template = test_template + {
        'link_with' : [
                libcore,
                libshared,
        ],
        'include_directories' : core_includes,
        'suite' : 'core',
}
