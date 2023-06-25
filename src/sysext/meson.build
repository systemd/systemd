# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_SYSEXT') != 1
        subdir_done()
endif

executables += [
        executable_template + {
                'name' : 'systemd-sysext',
                'public' : true,
                'sources' : files('sysext.c'),
                'install_dir' : rootbindir,
        },
]

meson.add_install_script(meson_make_symlink,
                         rootbindir / 'systemd-sysext',
                         rootbindir / 'systemd-confext')
