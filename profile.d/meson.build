# SPDX-License-Identifier: LGPL-2.1-or-later

install_data('70-systemd-shell-extra.sh', install_dir : shellprofiledir.startswith('/usr/') ? shellprofiledir : libexecdir / 'profile.d')

if conf.get('LINK_SHELL_EXTRA_DROPIN') == 1
        install_emptydir(shellprofiledir)

        meson.add_install_script(sh, '-c',
                ln_s.format(libexecdir / 'profile.d' / '70-systemd-shell-extra.sh', shellprofiledir / '70-systemd-shell-extra.sh'))
endif
