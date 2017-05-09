libcore_la_sources = '''
        unit.c
        unit.h
        unit-printf.c
        unit-printf.h
        job.c
        job.h
        manager.c
        manager.h
        transaction.c
        transaction.h
        load-fragment.c
        load-fragment.h
        service.c
        service.h
        socket.c
        socket.h
        busname.c
        busname.h
        bus-policy.c
        bus-policy.h
        target.c
        target.h
        device.c
        device.h
        mount.c
        mount.h
        automount.c
        automount.h
        swap.c
        swap.h
        timer.c
        timer.h
        path.c
        path.h
        slice.c
        slice.h
        scope.c
        scope.h
        load-dropin.c
        load-dropin.h
        execute.c
        execute.h
        dynamic-user.c
        dynamic-user.h
        kill.c
        kill.h
        dbus.c
        dbus.h
        dbus-manager.c
        dbus-manager.h
        dbus-unit.c
        dbus-unit.h
        dbus-job.c
        dbus-job.h
        dbus-service.c
        dbus-service.h
        dbus-socket.c
        dbus-socket.h
        dbus-busname.c
        dbus-busname.h
        dbus-target.c
        dbus-target.h
        dbus-device.c
        dbus-device.h
        dbus-mount.c
        dbus-mount.h
        dbus-automount.c
        dbus-automount.h
        dbus-swap.c
        dbus-swap.h
        dbus-timer.c
        dbus-timer.h
        dbus-path.c
        dbus-path.h
        dbus-slice.c
        dbus-slice.h
        dbus-scope.c
        dbus-scope.h
        dbus-execute.c
        dbus-execute.h
        dbus-kill.c
        dbus-kill.h
        dbus-cgroup.c
        dbus-cgroup.h
        cgroup.c
        cgroup.h
        selinux-access.c
        selinux-access.h
        selinux-setup.c
        selinux-setup.h
        smack-setup.c
        smack-setup.h
        ima-setup.c
        ima-setup.h
        locale-setup.h
        locale-setup.c
        hostname-setup.c
        hostname-setup.h
        machine-id-setup.c
        machine-id-setup.h
        mount-setup.c
        mount-setup.h
        kmod-setup.c
        kmod-setup.h
        loopback-setup.h
        loopback-setup.c
        namespace.c
        namespace.h
        killall.h
        killall.c
        audit-fd.c
        audit-fd.h
        show-status.c
        show-status.h
        emergency-action.c
        emergency-action.h
'''.split()

load_fragment_gperf_gperf = custom_target(
        'load-fragment-gperf.gperf',
        input : 'load-fragment-gperf.gperf.m4',
        output: 'load-fragment-gperf.gperf',
        command : [m4, '-P'] + m4_defines + ['@INPUT@'],
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

libcore = static_library(
        'core',
        libcore_la_sources,
        load_fragment_gperf_c,
        load_fragment_gperf_nulstr_c,
        include_directories : includes,
        link_with : [libshared_static],
        dependencies : [threads,
                        libseccomp,
                        libpam,
                        libaudit,
                        libkmod,
                        libapparmor,
                        libmount])

systemd_sources = files('main.c')

systemd_shutdown_sources = files('''
        shutdown.c
        umount.c
        umount.h
        mount-setup.c
        mount-setup.h
        killall.c
        killall.h
'''.split())

in_files = [['macros.systemd',   rpmmacrosdir],
            ['triggers.systemd', ''],
            ['systemd.pc',       pkgconfigdatadir]]

foreach item : in_files
        file = item[0]
        dir = item[1]

        # If 'no', disable generation completely.
        # If '', generate, but do not install.
        if dir != 'no'
                gen = configure_file(
                        input : file + '.in',
                        output : file,
                        configuration : substs)
                if dir != ''
                        install_data(gen,
                                     install_dir : dir)
                endif
        endif
endforeach

install_data('org.freedesktop.systemd1.conf',
             install_dir : dbuspolicydir)
install_data('org.freedesktop.systemd1.service',
             install_dir : dbussystemservicedir)

policy_in = configure_file(
        input : 'org.freedesktop.systemd1.policy.in.in',
        output : 'org.freedesktop.systemd1.policy.in',
        configuration : substs)

custom_target(
        'org.freedesktop.systemd1.policy',
        input : policy_in,
        output : 'org.freedesktop.systemd1.policy',
        command : intltool_command,
        install : install_polkit,
        install_dir : polkitpolicydir)

# TODO: this might work with meson from git, see
# https://github.com/mesonbuild/meson/issues/1441#issuecomment-283585493
#
# i18n.merge_file(
#   'org.freedesktop.systemd1.policy',
#   po_dir : po_dir,
#   input : policy_in,
#   output : 'org.freedesktop.systemd1.policy',
#   install : install_polkit,
#   install_dir : polkitpolicydir)

install_data('system.conf',
             'user.conf',
             install_dir : pkgsysconfdir)

meson.add_install_script('sh', '-c', mkdir_p.format(systemshutdowndir))
meson.add_install_script('sh', '-c', mkdir_p.format(systemsleepdir))
meson.add_install_script('sh', '-c', mkdir_p.format(systemgeneratordir))
meson.add_install_script('sh', '-c', mkdir_p.format(usergeneratordir))

meson.add_install_script('sh', '-c',
                         mkdir_p.format(join_paths(pkgsysconfdir, 'system/multi-user.target.wants')))
meson.add_install_script('sh', '-c',
                         mkdir_p.format(join_paths(pkgsysconfdir, 'system/getty.target.wants')))
meson.add_install_script('sh', '-c',
                         mkdir_p.format(join_paths(pkgsysconfdir, 'user')))
meson.add_install_script('sh', '-c',
                         mkdir_p.format(join_paths(sysconfdir, 'xdg/systemd')))
