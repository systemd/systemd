# SPDX-License-Identifier: LGPL-2.1-or-later

libcore_sources = files(
        'apparmor-setup.c',
        'audit-fd.c',
        'automount.c',
        'bpf-devices.c',
        'bpf-firewall.c',
        'bpf-foreign.c',
        'bpf-lsm.c',
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
        'execute.c',
        'generator-setup.c',
        'ima-setup.c',
        'import-creds.c',
        'job.c',
        'kill.c',
        'kmod-setup.c',
        'load-dropin.c',
        'load-fragment.c',
        'manager-dump.c',
        'manager-serialize.c',
        'manager.c',
        'mount.c',
        'namespace.c',
        'path.c',
        'restrict-ifaces.c',
        'scope.c',
        'selinux-access.c',
        'selinux-setup.c',
        'service.c',
        'show-status.c',
        'slice.c',
        'smack-setup.c',
        'socket.c',
        'swap.c',
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

subdir('bpf')

subdir('bpf/socket_bind')
if conf.get('BPF_FRAMEWORK') == 1
        libcore_sources += [socket_bind_skel_h]
        subdir('bpf/restrict_fs')
        libcore_sources += [restrict_fs_skel_h]
endif

subdir('bpf/restrict_ifaces')
if conf.get('BPF_FRAMEWORK') == 1
        libcore_sources += [restrict_ifaces_skel_h]
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

libcore = shared_library(
        libcore_name,
        libcore_sources,
        load_fragment_gperf_c,
        load_fragment_gperf_nulstr_c,
        include_directories : includes,
        c_args : ['-fvisibility=default'],
        link_args : ['-shared',
                     '-Wl,--version-script=' + libshared_sym_path],
        link_with : libshared,
        dependencies : [libacl,
                        libapparmor,
                        libaudit,
                        libblkid,
                        libdl,
                        libkmod,
                        libm,
                        libmount,
                        libpam,
                        librt,
                        libseccomp,
                        libselinux,
                        threads,
                        userspace,
                        versiondep],
        install : true,
        install_dir : rootpkglibdir)

core_includes = [includes, include_directories('.')]

systemd_sources = files(
        'main.c',
        'crash-handler.c',
)

in_files = [['system.conf',                     pkgsysconfdir],
            ['user.conf',                       pkgsysconfdir],
            ['systemd.pc',                      pkgconfigdatadir],
            ['org.freedesktop.systemd1.policy', polkitpolicydir]]

foreach item : in_files
        file = item[0]
        dir = item[1]

        custom_target(
                file,
                input : file + '.in',
                output: file,
                command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                install : (dir == pkgsysconfdir) ? install_sysconfdir_samples : (dir != 'no'),
                install_dir : dir)
endforeach

install_data('org.freedesktop.systemd1.conf',
             install_dir : dbuspolicydir)
install_data('org.freedesktop.systemd1.service',
             install_dir : dbussystemservicedir)

meson.add_install_script('sh', '-c', mkdir_p.format(systemshutdowndir))
meson.add_install_script('sh', '-c', mkdir_p.format(systemsleepdir))
meson.add_install_script('sh', '-c', mkdir_p.format(systemgeneratordir))
meson.add_install_script('sh', '-c', mkdir_p.format(usergeneratordir))

if install_sysconfdir
        meson.add_install_script('sh', '-c', mkdir_p.format(pkgsysconfdir / 'system'))
        meson.add_install_script('sh', '-c', mkdir_p.format(pkgsysconfdir / 'user'))
        meson.add_install_script('sh', '-c', mkdir_p.format(sysconfdir / 'xdg/systemd'))
endif

############################################################

test_core_base = {
        'link_with' : [libcore, libshared],
        'includes' : core_includes,
}

fuzzers += [
        {
                'sources' : files('fuzz-unit-file.c'),
                'link_with' : [
                        libcore,
                        libshared
                ],
                'dependencies' : libmount,
        },
]
