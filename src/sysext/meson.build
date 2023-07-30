# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_sysext_sources = files('sysext.c')

if conf.get('ENABLE_SYSEXT') == 1
        meson.add_install_script(meson_make_symlink,
                                 bindir / 'systemd-sysext',
                                 bindir / 'systemd-confext')
endif
