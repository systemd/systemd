# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-dissect',
                'conditions' : ['HAVE_BLKID'],
                'public' : true,
                'sources' : files('dissect.c'),
        },
]

if conf.get('HAVE_BLKID') == 1
        meson.add_install_script(meson_make_symlink,
                                 bindir / 'systemd-dissect',
                                 rootsbindir / 'mount.ddi')
endif
