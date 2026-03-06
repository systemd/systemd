# SPDX-License-Identifier: LGPL-2.1-or-later

install_data('70-systemd-shell-extra.sh', install_dir : shellprofiledir.startswith('/usr/') ? shellprofiledir : libexecdir / 'profile.d')
install_data('80-systemd-osc-context.sh', install_dir : shellprofiledir.startswith('/usr/') ? shellprofiledir : libexecdir / 'profile.d')

if (not shellprofiledir.startswith(sysconfdir) or install_sysconfdir) and conf.get('LINK_SHELL_EXTRA_DROPIN') == 1
        if meson.version().version_compare('>=1.3.0')
                install_symlink(
                        '70-systemd-shell-extra.sh',
                        pointing_to : fs.relative_to(libexecdir / 'profile.d' / '70-systemd-shell-extra.sh',
                                                     shellprofiledir),
                        install_dir : shellprofiledir)
        else
                install_emptydir(shellprofiledir)

                meson.add_install_script(sh, '-c',
                        ln_s.format(libexecdir / 'profile.d' / '70-systemd-shell-extra.sh',
                                    shellprofiledir / '70-systemd-shell-extra.sh'))
        endif
endif

if (not shellprofiledir.startswith(sysconfdir) or install_sysconfdir) and conf.get('LINK_OSC_CONTEXT_DROPIN') == 1
        if meson.version().version_compare('>=1.3.0')
                install_symlink(
                        '80-systemd-osc-context.sh',
                        pointing_to : fs.relative_to(libexecdir / 'profile.d' / '80-systemd-osc-context.sh',
                                                     shellprofiledir),
                        install_dir : shellprofiledir)
        else
                install_emptydir(shellprofiledir)

                meson.add_install_script(sh, '-c',
                        ln_s.format(libexecdir / 'profile.d' / '80-systemd-osc-context.sh',
                                    shellprofiledir / '80-systemd-osc-context.sh'))
        endif
endif
