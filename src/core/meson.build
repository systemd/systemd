# SPDX-License-Identifier: LGPL-2.1+

libcore_shared_sources = '''
        killall.c
        killall.h
        loopback-setup.c
        loopback-setup.h
        machine-id-setup.c
        machine-id-setup.h
        mount-setup.c
        mount-setup.h
'''.split()

libcore_sources = '''
        audit-fd.c
        audit-fd.h
        automount.c
        automount.h
        bpf-devices.c
        bpf-devices.h
        bpf-firewall.c
        bpf-firewall.h
        cgroup.c
        cgroup.h
        chown-recursive.c
        chown-recursive.h
        dbus-automount.c
        dbus-automount.h
        dbus-cgroup.c
        dbus-cgroup.h
        dbus-device.c
        dbus-device.h
        dbus-execute.c
        dbus-execute.h
        dbus-job.c
        dbus-job.h
        dbus-kill.c
        dbus-kill.h
        dbus-manager.c
        dbus-manager.h
        dbus-mount.c
        dbus-mount.h
        dbus-path.c
        dbus-path.h
        dbus-scope.c
        dbus-scope.h
        dbus-service.c
        dbus-service.h
        dbus-slice.c
        dbus-slice.h
        dbus-socket.c
        dbus-socket.h
        dbus-swap.c
        dbus-swap.h
        dbus-target.c
        dbus-target.h
        dbus-timer.c
        dbus-timer.h
        dbus-unit.c
        dbus-unit.h
        dbus-util.c
        dbus-util.h
        dbus.c
        dbus.h
        device.c
        device.h
        dynamic-user.c
        dynamic-user.h
        efi-random.c
        efi-random.h
        emergency-action.c
        emergency-action.h
        execute.c
        execute.h
        hostname-setup.c
        hostname-setup.h
        ima-setup.c
        ima-setup.h
        ip-address-access.c
        ip-address-access.h
        job.c
        job.h
        kill.c
        kill.h
        kmod-setup.c
        kmod-setup.h
        load-dropin.c
        load-dropin.h
        load-fragment.c
        load-fragment.h
        locale-setup.c
        locale-setup.h
        manager.c
        manager.h
        mount.c
        mount.h
        namespace.c
        namespace.h
        path.c
        path.h
        scope.c
        scope.h
        selinux-access.c
        selinux-access.h
        selinux-setup.c
        selinux-setup.h
        service.c
        service.h
        show-status.c
        show-status.h
        slice.c
        slice.h
        smack-setup.c
        smack-setup.h
        socket.c
        socket.h
        swap.c
        swap.h
        target.c
        target.h
        timer.c
        timer.h
        transaction.c
        transaction.h
        unit-printf.c
        unit-printf.h
        unit.c
        unit.h
'''.split()

load_fragment_gperf_gperf = custom_target(
        'load-fragment-gperf.gperf',
        input : 'load-fragment-gperf.gperf.m4',
        output: 'load-fragment-gperf.gperf',
        command : [meson_apply_m4, config_h, '@INPUT@'],
        capture : true)

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

# A convenience library to share code with other binaries:
# systemd-shutdown, systemd-remount-fs, systemd-machine-id-setup, …
libcore_shared = static_library(
        'core-shared',
        libcore_shared_sources,
        include_directories : includes,
        dependencies : [versiondep,
                        libmount])

libcore = static_library(
        'core',
        libcore_sources,
        load_fragment_gperf_c,
        load_fragment_gperf_nulstr_c,
        include_directories : includes,
        link_whole : libcore_shared,
        dependencies : [versiondep,
                        threads,
                        librt,
                        libseccomp,
                        libpam,
                        libaudit,
                        libkmod,
                        libapparmor,
                        libselinux,
                        libmount])

systemd_sources = files('main.c')

in_files = [['macros.systemd',   rpmmacrosdir],
            ['system.conf',      pkgsysconfdir],
            ['user.conf',        pkgsysconfdir],
            ['systemd.pc',       pkgconfigdatadir],
            ['triggers.systemd', '']]

foreach item : in_files
        file = item[0]
        dir = item[1]

        configure_file(
                input : file + '.in',
                output : file,
                configuration : substs,
                install_dir : dir == 'no' ? '' : dir)
endforeach

install_data('org.freedesktop.systemd1.conf',
             install_dir : dbuspolicydir)

policy = configure_file(
        input : 'org.freedesktop.systemd1.policy.in',
        output : 'org.freedesktop.systemd1.policy',
        configuration : substs)
install_data(policy,
             install_dir : polkitpolicydir)

meson.add_install_script('sh', '-c', mkdir_p.format(systemshutdowndir))
meson.add_install_script('sh', '-c', mkdir_p.format(systemsleepdir))
meson.add_install_script('sh', '-c', mkdir_p.format(systemgeneratordir))
meson.add_install_script('sh', '-c', mkdir_p.format(usergeneratordir))

meson.add_install_script('sh', '-c', mkdir_p.format(join_paths(pkgsysconfdir, 'system')))
meson.add_install_script('sh', '-c', mkdir_p.format(join_paths(pkgsysconfdir, 'user')))
meson.add_install_script('sh', '-c', mkdir_p.format(join_paths(sysconfdir, 'xdg/systemd')))
