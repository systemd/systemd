# SPDX-License-Identifier: LGPL-2.1+

systemd_logind_sources = files('''
        logind.c
        logind.h
'''.split())

logind_gperf_c = custom_target(
        'logind_gperf.c',
        input : 'logind-gperf.gperf',
        output : 'logind-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

liblogind_core_sources = files('''
        logind-acl.h
        logind-action.c
        logind-action.h
        logind-brightness.c
        logind-brightness.h
        logind-button.c
        logind-button.h
        logind-core.c
        logind-dbus.c
        logind-dbus.h
        logind-device.c
        logind-device.h
        logind-inhibit.c
        logind-inhibit.h
        logind-seat-dbus.c
        logind-seat-dbus.h
        logind-seat.c
        logind-seat.h
        logind-session-dbus.c
        logind-session-dbus.h
        logind-session-device.c
        logind-session-device.h
        logind-session.c
        logind-session.h
        logind-user-dbus.c
        logind-user-dbus.h
        logind-user.c
        logind-user.h
        logind-utmp.c
'''.split())

liblogind_core_sources += [logind_gperf_c]

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

user_runtime_dir_sources = files('''
        user-runtime-dir.c
'''.split())

pam_systemd_sym = 'src/login/pam_systemd.sym'
pam_systemd_c = files('pam_systemd.c')

if conf.get('ENABLE_LOGIND') == 1
        logind_conf = configure_file(
                input : 'logind.conf.in',
                output : 'logind.conf',
                configuration : substs)
        install_data(logind_conf,
                     install_dir : pkgsysconfdir)

        install_data('org.freedesktop.login1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.login1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.login1.policy',
                     install_dir : polkitpolicydir)

        install_data('70-power-switch.rules', install_dir : udevrulesdir)

        seat_rules = configure_file(
                input : '71-seat.rules.in',
                output : '71-seat.rules',
                configuration : substs)
        install_data(seat_rules,
                     install_dir : udevrulesdir)

        custom_target(
                '70-uaccess.rules',
                input : '70-uaccess.rules.m4',
                output: '70-uaccess.rules',
                command : [meson_apply_m4, config_h, '@INPUT@'],
                capture : true,
                install : conf.get('HAVE_ACL') == 1,
                install_dir : udevrulesdir)

        custom_target(
                '73-seat-late.rules',
                input : '73-seat-late.rules.m4',
                output: '73-seat-late.rules',
                command : [meson_apply_m4, config_h, '@INPUT@'],
                capture : true,
                install : true,
                install_dir : udevrulesdir)

        custom_target(
                'systemd-user',
                input : 'systemd-user.m4',
                output: 'systemd-user',
                command : [meson_apply_m4, config_h, '@INPUT@'],
                capture : true,
                install : pamconfdir != 'no',
                install_dir : pamconfdir)
endif
