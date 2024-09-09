# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        generator_template + {
                'name' : 'systemd-ssh-generator',
                'sources' : files('ssh-generator.c'),
        },
        libexec_template + {
                'name' : 'systemd-ssh-proxy',
                'sources' : files('ssh-proxy.c'),
        },
]

if conf.get('ENABLE_SSH_PROXY_CONFIG') == 1
        custom_target(
                '20-systemd-ssh-proxy.conf',
                input : '20-systemd-ssh-proxy.conf.in',
                output : '20-systemd-ssh-proxy.conf',
                command : [jinja2_cmdline, '@INPUT@', '@OUTPUT@'],
                install : true,
                install_dir : sshconfdir.startswith('/usr/') ? sshconfdir : libexecdir / 'ssh_config.d')

        if conf.get('LINK_SSH_PROXY_DROPIN') == 1
                install_emptydir(sshconfdir)

                meson.add_install_script(sh, '-c',
                        ln_s.format(libexecdir / 'ssh_config.d' / '20-systemd-ssh-proxy.conf', sshconfdir / '20-systemd-ssh-proxy.conf'))
        endif
endif
