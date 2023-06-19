# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-fstab-generator',
        },
        generator_template + {
                'sources' : files('fstab-generator.c'),
        },
]]

meson.add_install_script(meson_make_symlink,
                         systemgeneratordir / 'systemd-fstab-generator',
                         rootlibexecdir / 'systemd-sysroot-fstab-check')
