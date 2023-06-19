# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [[
        {
                'name' : 'systemd-mount',
                'public' : true,
        },
        executable_template + {
                'sources' : files('mount-tool.c'),
                'dependencies' : [libmount,
                                  userspace,
                                  versiondep],
        },
]]

meson.add_install_script(meson_make_symlink,
                         'systemd-mount', bindir / 'systemd-umount')
