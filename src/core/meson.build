# SPDX-License-Identifier: LGPL-2.1-or-later

libcore_sources = files(
        'audit-fd.c',
        'automount.c',
        'bpf-devices.c',
        'bpf-firewall.c',
        'bpf-foreign.c',
        'bpf-restrict-fs.c',
        'bpf-restrict-ifaces.c',
        'bpf-socket-bind.c',
        'cgroup.c',
        'core-varlink.c',
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
        'efi-random.c',
        'emergency-action.c',
        'exec-credential.c',
        'execute.c',
        'execute-serialize.c',
        'generator-setup.c',
        'import-creds.c',
        'job.c',
        'kill.c',
        'load-dropin.c',
        'load-fragment.c',
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
)

if conf.get('BPF_FRAMEWORK') == 1
        libcore_sources += files(
                'bpf-util.c',
        )
endif

subdir('bpf/socket_bind')
subdir('bpf/restrict_fs')
subdir('bpf/restrict_ifaces')

if conf.get('BPF_FRAMEWORK') == 1
        libcore_sources += [
                socket_bind_skel_h,
                restrict_fs_skel_h,
                restrict_ifaces_skel_h]
endif

load_fragment_gperf_gperf = custom_target(
        'load-fragment-gperf.gperf',
        input : 'load-fragment-gperf.gperf.in',
        output: 'load-fragment-gperf.gperf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'])

load_fragment_gperf_c = custom_target(
        'load-fragment-gperf.c',
        input : load_fragment_gperf_gperf,
        output : 'load-fragment-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

awkscript = 'load-fragment-gperf-nulstr.awk'
load_fragment_gperf_nulstr_c = custom_target(
        'load-fragment-gperf-nulstr.c',
        input : [awkscript, load_fragment_gperf_gperf],
        output : 'load-fragment-gperf-nulstr.c',
        command : [awk, '-f', '@INPUT0@', '@INPUT1@'],
        capture : true)

libcore_name = 'systemd-core-@0@'.format(shared_lib_tag)

libcore_static = static_library(
        libcore_name,
        libcore_sources,
        load_fragment_gperf_c,
        load_fragment_gperf_nulstr_c,
        include_directories : includes,
        c_args : ['-fvisibility=default'],
        dependencies : [libacl,
                        libaudit,
                        libblkid,
                        libdl,
                        libm,
                        libmount,
                        libpam,
                        librt,
                        libseccomp,
                        libselinux,
                        threads,
                        userspace],
        build_by_default : false)

libcore = shared_library(
        libcore_name,
        c_args : ['-fvisibility=default'],
        link_args : ['-shared',
                     '-Wl,--version-script=' + libshared_sym_path],
        link_depends : libshared_sym_path,
        link_whole: libcore_static,
        link_with : libshared,
        install : true,
        install_dir : pkglibdir)

core_includes = [includes, include_directories('.')]

systemd_sources = files(
        'main.c',
        'crash-handler.c',
        'clock-warp.c',
        'kmod-setup.c',
        'apparmor-setup.c',
        'ima-setup.c',
        'ipe-setup.c',
        'selinux-setup.c',
        'smack-setup.c',
)

systemd_executor_sources = files(
        'executor.c',
        'exec-invoke.c',
)

executor_libs = get_option('link-executor-shared') ? \
        [
                libcore,
                libshared,
        ] : [
                libcore_static,
                libshared_static,
                libbasic_static,
                libsystemd_static,
        ]

executables += [
        libexec_template + {
                'name' : 'systemd',
                'dbus' : true,
                'public' : true,
                'sources' : systemd_sources,
                'link_with' : [
                        libcore,
                        libshared,
                ],
                'dependencies' : [
                        libapparmor,
                        libkmod_cflags,
                        libseccomp,
                        libselinux,
                ],
        },
        libexec_template + {
                'name' : 'systemd-executor',
                'public' : true,
                'sources' : systemd_executor_sources,
                'include_directories' : core_includes,
                'link_with' : executor_libs,
                'dependencies' : [
                        libapparmor,
                        libpam,
                        libseccomp,
                        libselinux,
                ],
        },
        fuzz_template + {
                'sources' : files('fuzz-unit-file.c'),
                'link_with' : [
                        libcore,
                        libshared
                ],
                'dependencies' : libmount,
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

in_files = [['system.conf',                     pkgconfigfiledir],
            ['user.conf',                       pkgconfigfiledir],
            ['org.freedesktop.systemd1.policy', polkitpolicydir]]

foreach item : in_files
        file = item[0]
        dir = item[1]

        custom_target(
                file,
                input : file + '.in',
                output: file,
                command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                install : (dir == pkgconfigfiledir) ? install_sysconfdir_samples : (dir != 'no'),
                install_dir : dir)
endforeach

systemd_pc = custom_target(
        'systemd.pc',
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

install_emptydir(systemshutdowndir)
install_emptydir(systemsleepdir)
install_emptydir(systemgeneratordir)
install_emptydir(usergeneratordir)

if install_sysconfdir
        install_emptydir(pkgsysconfdir / 'system')
        install_emptydir(pkgsysconfdir / 'user')
        install_emptydir(sysconfdir / 'xdg/systemd')
        meson.add_install_script(sh, '-c', ln_s.format(pkgsysconfdir / 'user',
                                                       sysconfdir / 'xdg/systemd/user'))
endif

install_emptydir(sbindir)
meson.add_install_script(sh, '-c', ln_s.format(libexecdir / 'systemd', sbindir / 'init'))

############################################################

core_test_template = test_template + {
        'link_with' : [
                libcore,
                libshared,
        ],
        'include_directories' : core_includes,
        'suite' : 'core',
}
