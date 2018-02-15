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

systemd_logind_sources = files('''
        logind.c
        logind.h
'''.split())

logind_gperf_c = custom_target(
        'logind_gperf.c',
        input : 'logind-gperf.gperf',
        output : 'logind-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

systemd_logind_sources += [logind_gperf_c]


liblogind_core_sources = files('''
        logind-core.c
        logind-device.c
        logind-device.h
        logind-button.c
        logind-button.h
        logind-action.c
        logind-action.h
        logind-seat.c
        logind-seat.h
        logind-session.c
        logind-session.h
        logind-session-device.c
        logind-session-device.h
        logind-user.c
        logind-user.h
        logind-inhibit.c
        logind-inhibit.h
        logind-dbus.c
        logind-session-dbus.c
        logind-seat-dbus.c
        logind-user-dbus.c
        logind-utmp.c
        logind-acl.h
'''.split())

logind_acl_c = files('logind-acl.c')
if conf.get('HAVE_ACL') == 1
        liblogind_core_sources += logind_acl_c
endif

liblogind_core = static_library(
        'logind-core',
        liblogind_core_sources,
        include_directories : includes,
        dependencies : [libacl])

loginctl_sources = files('''
        loginctl.c
        sysfs-show.h
        sysfs-show.c
'''.split())

if conf.get('ENABLE_LOGIND') == 1
        logind_conf = configure_file(
                input : 'logind.conf.in',
                output : 'logind.conf',
                configuration : substs)
        install_data(logind_conf,
                     install_dir : pkgsysconfdir)

        pam_systemd_sym = 'src/login/pam_systemd.sym'
        pam_systemd_c = files('pam_systemd.c')

        install_data('org.freedesktop.login1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.login1.service',
                     install_dir : dbussystemservicedir)

        policy = configure_file(
                input : 'org.freedesktop.login1.policy.in',
                output : 'org.freedesktop.login1.policy',
                configuration : substs)
        install_data(policy,
                     install_dir : polkitpolicydir)

        install_data('70-power-switch.rules', install_dir : udevrulesdir)

        if conf.get('HAVE_ACL') == 1
                install_data('70-uaccess.rules', install_dir : udevrulesdir)
        endif

        seat_rules = configure_file(
                input : '71-seat.rules.in',
                output : '71-seat.rules',
                configuration : substs)
        install_data(seat_rules,
                     install_dir : udevrulesdir)

        custom_target(
                '73-seat-late.rules',
                input : '73-seat-late.rules.m4',
                output: '73-seat-late.rules',
                command : [m4, '-P'] + m4_defines + ['@INPUT@'],
                capture : true,
                install : true,
                install_dir : udevrulesdir)

        custom_target(
                'systemd-user',
                input : 'systemd-user.m4',
                output: 'systemd-user',
                command : [m4, '-P'] + m4_defines + ['@INPUT@'],
                capture : true,
                install : pamconfdir != 'no',
                install_dir : pamconfdir)
endif
