# SPDX-License-Identifier: LGPL-2.1+
#
# Copyright 2017 Zbigniew Jędrzejewski-Szmek
#
# systemd is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# systemd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with systemd; If not, see <http://www.gnu.org/licenses/>.

libcore_la_sources = '''
        audit-fd.c
        audit-fd.h
        automount.c
        automount.h
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
        killall.c
        killall.h
        kmod-setup.c
        kmod-setup.h
        load-dropin.c
        load-dropin.h
        load-fragment.c
        load-fragment.h
        locale-setup.c
        locale-setup.h
        loopback-setup.c
        loopback-setup.h
        machine-id-setup.c
        machine-id-setup.h
        manager.c
        manager.h
        mount-setup.c
        mount-setup.h
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

policy = configure_file(
        input : 'org.freedesktop.systemd1.policy.in.in',
        output : 'org.freedesktop.systemd1.policy',
        configuration : substs)
install_data(policy,
             install_dir : polkitpolicydir)

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
