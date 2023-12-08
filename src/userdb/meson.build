# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-userwork',
                'conditions' : ['ENABLE_USERDB'],
                'sources' : files('userwork.c'),
                'dependencies' : threads,
        },
        libexec_template + {
                'name' : 'systemd-userdbd',
                'conditions' : ['ENABLE_USERDB'],
                'sources' : files(
                        'userdbd-manager.c',
                        'userdbd.c',
                ),
                'dependencies' : threads,
        },
        executable_template + {
                'name' : 'userdbctl',
                'conditions' : ['ENABLE_USERDB'],
                'sources' : files('userdbctl.c'),
                'dependencies' : threads,
        },
]

custom_target(
        '20-systemd-userdb.conf',
        input : '20-systemd-userdb.conf.in',
        output : '20-systemd-userdb.conf',
        command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
        install : conf.get('ENABLE_USERDB') == 1 and sshdconfdir != 'no',
        install_dir : libexecdir / 'sshd_config.d')

install_emptydir(sshdconfdir)

meson.add_install_script(sh, '-c',
        ln_s.format(libexecdir / 'sshd_config.d' / '20-systemd-userdb.conf', sshdconfdir / '20-systemd-userdb.conf'))
