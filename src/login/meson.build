# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_logind_sources = files(
        'logind.c',
)

logind_gperf_c = custom_target(
        'logind_gperf.c',
        input : 'logind-gperf.gperf',
        output : 'logind-gperf.c',
        command : [gperf, '@INPUT@', '--output-file', '@OUTPUT@'])

liblogind_core_sources = files(
        'logind-action.c',
        'logind-brightness.c',
        'logind-button.c',
        'logind-core.c',
        'logind-dbus.c',
        'logind-device.c',
        'logind-inhibit.c',
        'logind-polkit.c',
        'logind-seat-dbus.c',
        'logind-seat.c',
        'logind-session-dbus.c',
        'logind-session-device.c',
        'logind-session.c',
        'logind-user-dbus.c',
        'logind-user.c',
        'logind-varlink.c',
        'logind-wall.c',
)

liblogind_core_sources += [logind_gperf_c]

liblogind_core = static_library(
        'logind-core',
        liblogind_core_sources,
        include_directories : includes,
        dependencies : [libacl,
                        userspace],
        build_by_default : false)

loginctl_sources = files(
        'loginctl.c',
        'sysfs-show.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-logind',
                'dbus' : true,
                'conditions' : ['ENABLE_LOGIND'],
                'sources' : systemd_logind_sources,
                'link_with' : [
                        liblogind_core,
                        libshared,
                ],
                'dependencies' : [
                        libacl,
                        threads,
                ],
        },
        executable_template + {
                'name' : 'loginctl',
                'public' : true,
                'conditions' : ['ENABLE_LOGIND'],
                'sources' : loginctl_sources,
                'dependencies' : [
                        liblz4_cflags,
                        libxz_cflags,
                        libzstd_cflags,
                        threads,
                ],
        },
        executable_template + {
                'name' : 'systemd-inhibit',
                'public' : true,
                'conditions' : ['ENABLE_LOGIND'],
                'sources' : files('inhibit.c'),
        },
        libexec_template + {
                'name' : 'systemd-user-runtime-dir',
                'conditions' : ['ENABLE_LOGIND'],
                'sources' : files('user-runtime-dir.c'),
        },
        test_template + {
                'sources' : files('test-inhibit.c'),
                'type' : 'manual',
        },
        test_template + {
                'sources' : files('test-login-tables.c'),
                'link_with' : [
                        liblogind_core,
                        libshared,
                ],
                'dependencies' : threads,
        },
        test_template + {
                'sources' : files('test-session-properties.c'),
                'type' : 'manual',
        },
]

simple_tests += files(
        'test-login-shared.c'
)

modules += [
        pam_template + {
                'name' : 'pam_systemd',
                'conditions' : [
                        'ENABLE_LOGIND',
                        'HAVE_PAM',
                ],
                'sources' : files('pam_systemd.c'),
                'version-script' : meson.current_source_dir() / 'pam_systemd.sym',
        },
        pam_template + {
                'name' : 'pam_systemd_loadkey',
                'conditions' : [
                        'HAVE_PAM',
                ],
                'sources' : files('pam_systemd_loadkey.c'),
                'version-script' : meson.current_source_dir() / 'pam_systemd_loadkey.sym',
        },
]

enable_logind = conf.get('ENABLE_LOGIND') == 1

custom_target(
        'logind.conf',
        input : 'logind.conf.in',
        output : 'logind.conf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : enable_logind and install_sysconfdir_samples and pkgsysconfdir != 'no',
        install_dir : pkgconfigfiledir)

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
