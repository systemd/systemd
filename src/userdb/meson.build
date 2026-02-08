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

if conf.get('ENABLE_SSH_USERDB_CONFIG') == 1
        custom_target(
                input : '20-systemd-userdb.conf.in',
                output : '20-systemd-userdb.conf',
                command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                install : true,
                install_dir : sshdconfdir.startswith('/usr/') ? sshdconfdir : libexecdir / 'sshd_config.d')

        if (not sshdconfdir.startswith(sysconfdir) or install_sysconfdir) and conf.get('LINK_SSHD_USERDB_DROPIN') == 1
                if meson.version().version_compare('>=1.3.0')
                        install_symlink(
                                '20-systemd-userdb.conf',
                                pointing_to : fs.relative_to(libexecdir / 'sshd_config.d' / '20-systemd-userdb.conf',
                                                             sshdconfdir),
                                install_dir : sshdconfdir)
                else
                        install_emptydir(sshdconfdir)

                        meson.add_install_script(sh, '-c',
                                ln_s.format(libexecdir / 'sshd_config.d' / '20-systemd-userdb.conf',
                                            sshdconfdir / '20-systemd-userdb.conf'))
                endif
        endif
endif
