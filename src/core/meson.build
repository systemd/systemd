# SPDX-License-Identifier: LGPL-2.1-or-later

libcore_sources = files(
        'apparmor-setup.c',
        'apparmor-setup.h',
        'audit-fd.c',
        'audit-fd.h',
        'automount.c',
        'automount.h',
        'bpf-devices.c',
        'bpf-devices.h',
        'bpf-firewall.c',
        'bpf-firewall.h',
        'bpf-foreign.c',
        'bpf-foreign.h',
        'bpf-lsm.c',
        'bpf-lsm.h',
        'bpf-socket-bind.c',
        'bpf-socket-bind.h',
        'cgroup.c',
        'cgroup.h',
        'core-varlink.c',
        'core-varlink.h',
        'dbus-automount.c',
        'dbus-automount.h',
        'dbus-cgroup.c',
        'dbus-cgroup.h',
        'dbus-device.c',
        'dbus-device.h',
        'dbus-execute.c',
        'dbus-execute.h',
        'dbus-job.c',
        'dbus-job.h',
        'dbus-kill.c',
        'dbus-kill.h',
        'dbus-manager.c',
        'dbus-manager.h',
        'dbus-mount.c',
        'dbus-mount.h',
        'dbus-path.c',
        'dbus-path.h',
        'dbus-scope.c',
        'dbus-scope.h',
        'dbus-service.c',
        'dbus-service.h',
        'dbus-slice.c',
        'dbus-slice.h',
        'dbus-socket.c',
        'dbus-socket.h',
        'dbus-swap.c',
        'dbus-swap.h',
        'dbus-target.c',
        'dbus-target.h',
        'dbus-timer.c',
        'dbus-timer.h',
        'dbus-unit.c',
        'dbus-unit.h',
        'dbus-util.c',
        'dbus-util.h',
        'dbus.c',
        'dbus.h',
        'device.c',
        'device.h',
        'dynamic-user.c',
        'dynamic-user.h',
        'efi-random.c',
        'efi-random.h',
        'emergency-action.c',
        'emergency-action.h',
        'execute.c',
        'execute.h',
        'generator-setup.c',
        'generator-setup.h',
        'ima-setup.c',
        'ima-setup.h',
        'import-creds.c',
        'import-creds.h',
        'job.c',
        'job.h',
        'kill.c',
        'kill.h',
        'kmod-setup.c',
        'kmod-setup.h',
        'load-dropin.c',
        'load-dropin.h',
        'load-fragment.c',
        'load-fragment.h',
        'locale-setup.c',
        'locale-setup.h',
        'manager-dump.c',
        'manager-dump.h',
        'manager-serialize.c',
        'manager-serialize.h',
        'manager.c',
        'manager.h',
        'mount.c',
        'mount.h',
        'namespace.c',
        'namespace.h',
        'path.c',
        'path.h',
        'restrict-ifaces.c',
        'restrict-ifaces.h',
        'scope.c',
        'scope.h',
        'selinux-access.c',
        'selinux-access.h',
        'selinux-setup.c',
        'selinux-setup.h',
        'service.c',
        'service.h',
        'show-status.c',
        'show-status.h',
        'slice.c',
        'slice.h',
        'smack-setup.c',
        'smack-setup.h',
        'socket.c',
        'socket.h',
        'swap.c',
        'swap.h',
        'target.c',
        'target.h',
        'timer.c',
        'timer.h',
        'transaction.c',
        'transaction.h',
        'unit-dependency-atom.c',
        'unit-dependency-atom.h',
        'unit-printf.c',
        'unit-printf.h',
        'unit-serialize.c',
        'unit-serialize.h',
        'unit.c',
        'unit.h',
)

if conf.get('BPF_FRAMEWORK') == 1
        libcore_sources += files(
                'bpf-util.c',
                'bpf-util.h',
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
        dependencies : [versiondep,
                        threads,
                        libdl,
                        librt,
                        libseccomp,
                        libpam,
                        libaudit,
                        libkmod,
                        libapparmor,
                        libselinux,
                        libmount,
                        libblkid,
                        libacl],
        install : true,
        install_dir : rootlibexecdir)

core_includes = [includes, include_directories('.')]

systemd_sources = files(
        'main.c',
        'main.h',
        'crash-handler.c',
        'crash-handler.h',
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

fuzzers += [
        [files('fuzz-unit-file.c'),
         [libcore,
          libshared],
         [libmount]],
]
