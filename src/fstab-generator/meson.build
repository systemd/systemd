# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        generator_template + {
                'name' : 'systemd-fstab-generator',
                'sources' : files('fstab-generator.c'),
        },
]

meson.add_install_script(meson_make_symlink,
                         systemgeneratordir / 'systemd-fstab-generator',
                         libexecdir / 'systemd-sysroot-fstab-check')
