# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_sysext_sources = files('sysext.c')

meson.add_install_script(meson_make_symlink,
                         rootbindir / 'systemd-sysext',
                         rootbindir / 'systemd-syscfg')