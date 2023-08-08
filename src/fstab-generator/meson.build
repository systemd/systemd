# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        generator_template + {
                'name' : 'systemd-fstab-generator',
                'sources' : files('fstab-generator.c'),
        },
]

meson.add_install_script(sh, '-c',
                         ln_s.format(systemgeneratordir / 'systemd-fstab-generator',
                                     libexecdir / 'systemd-sysroot-fstab-check'))
