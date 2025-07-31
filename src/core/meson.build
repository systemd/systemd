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
        'varlink.c',
        'varlink-cgroup.c',
        'varlink-common.c',
        'varlink-dynamic-user.c',
        'varlink-manager.c',
        'varlink-unit.c',
)

subdir('bpf/socket-bind')
subdir('bpf/restrict-fs')
subdir('bpf/restrict-ifaces')

if conf.get('BPF_FRAMEWORK') == 1
        libcore_sources += [
                socket_bind_skel_h,
                restrict_fs_skel_h,
                restrict_ifaces_skel_h]
endif

sources += libcore_sources

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

libcore_static = static_library(
        libcore_name,
        libcore_sources,
        include_directories : [includes, include_directories('.')],
        implicit_include_directories : false,
        c_args : ['-fvisibility=default'],
        dependencies : [libacl,
                        libaudit,
                        libblkid,
                        libdl,
                        libm,
                        libmount,
                        librt,
                        libseccomp,
                        libselinux,
                        threads,
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
        'efi-random.c',
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
                libc_wrapper_static,
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
                        libapparmor_cflags,
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
                        libapparmor_cflags,
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
