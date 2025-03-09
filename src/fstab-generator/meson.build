# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        generator_template + {
                'name' : 'systemd-fstab-generator',
                'sources' : files('fstab-generator.c'),
        },
]

assert(libexecdir / fs.name(systemgeneratordir) == systemgeneratordir)
install_symlink('systemd-sysroot-fstab-check',
                pointing_to : fs.name(systemgeneratordir) / 'systemd-fstab-generator',
                install_dir : libexecdir)
