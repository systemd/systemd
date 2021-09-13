# SPDX-License-Identifier: LGPL-2.1-or-later

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
        logind-polkit.c
        logind-polkit.h
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

enable_logind = conf.get('ENABLE_LOGIND') == 1
in_files = [
        ['logind.conf',        pkgsysconfdir, enable_logind and install_sysconfdir_samples],
        ['70-uaccess.rules',   udevrulesdir,  enable_logind and conf.get('HAVE_ACL') == 1],
        ['71-seat.rules',      udevrulesdir,  enable_logind],
        ['73-seat-late.rules', udevrulesdir,  enable_logind],
        ['systemd-user',       pamconfdir,    enable_logind]]

foreach tuple : in_files
        file = tuple[0]
        dir = tuple[1]
        install = (dir == pkgsysconfdir) ? install_sysconfdir_samples : (dir != 'no')
        custom_target(
                file,
                input : file + '.in',
                output: file,
                command : [meson_render_jinja2, config_h, '@INPUT@'],
                capture : true,
                install : tuple[2] and install,
                install_dir : dir)
endforeach

if enable_logind
        install_data('org.freedesktop.login1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.login1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.login1.policy',
                     install_dir : polkitpolicydir)
        install_data('70-power-switch.rules',
                     install_dir : udevrulesdir)
endif

############################################################

tests += [
        [['src/login/test-login-shared.c']],

        [['src/login/test-inhibit.c'],
         [], [], [], '', 'manual'],

        [['src/login/test-login-tables.c'],
         [liblogind_core,
          libshared],
         [threads]],
]
