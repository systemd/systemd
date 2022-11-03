# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_logind_sources = files(
        'logind.c',
        'logind.h',
)

logind_gperf_c = custom_target(
        'logind_gperf.c',
        input : 'logind-gperf.gperf',
        output : 'logind-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

liblogind_core_sources = files(
        'logind-action.c',
        'logind-action.h',
        'logind-brightness.c',
        'logind-brightness.h',
        'logind-button.c',
        'logind-button.h',
        'logind-core.c',
        'logind-dbus.c',
        'logind-dbus.h',
        'logind-device.c',
        'logind-device.h',
        'logind-inhibit.c',
        'logind-inhibit.h',
        'logind-polkit.c',
        'logind-polkit.h',
        'logind-seat-dbus.c',
        'logind-seat-dbus.h',
        'logind-seat.c',
        'logind-seat.h',
        'logind-session-dbus.c',
        'logind-session-dbus.h',
        'logind-session-device.c',
        'logind-session-device.h',
        'logind-session.c',
        'logind-session.h',
        'logind-user-dbus.c',
        'logind-user-dbus.h',
        'logind-user.c',
        'logind-user.h',
        'logind-utmp.c',
)

liblogind_core_sources += [logind_gperf_c]

liblogind_core = static_library(
        'logind-core',
        liblogind_core_sources,
        include_directories : includes,
        dependencies : libacl,
        build_by_default : false)

loginctl_sources = files(
        'loginctl.c',
        'sysfs-show.h',
        'sysfs-show.c',
)

user_runtime_dir_sources = files('user-runtime-dir.c')

pam_systemd_sym = 'src/login/pam_systemd.sym'
pam_systemd_c = files('pam_systemd.c')

enable_logind = conf.get('ENABLE_LOGIND') == 1

custom_target(
        'logind.conf',
        input : 'logind.conf.in',
        output : 'logind.conf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : enable_logind and install_sysconfdir_samples and pkgsysconfdir != 'no',
        install_dir : pkgsysconfdir)

custom_target(
        'systemd-user',
        input : 'systemd-user.in',
        output : 'systemd-user',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : enable_logind and pamconfdir != 'no',
        install_dir : pamconfdir)

if enable_logind
        install_data('org.freedesktop.login1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.login1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.login1.policy',
                     install_dir : polkitpolicydir)
endif

############################################################

tests += [
        [files('test-login-shared.c')],

        [files('test-inhibit.c'),
         [], [], [], '', 'manual'],

        [files('test-login-tables.c'),
         [liblogind_core,
          libshared],
         [threads]],

        [files('test-session-properties.c'),
         [], [], [], '', 'manual'],
]
