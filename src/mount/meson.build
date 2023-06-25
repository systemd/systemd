# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-mount',
                'public' : true,
                'sources' : files('mount-tool.c'),
                'dependencies' : libmount,
        },
]

meson.add_install_script(meson_make_symlink,
                         'systemd-mount', bindir / 'systemd-umount')
