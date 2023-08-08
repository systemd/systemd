# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-mount',
                'public' : true,
                'sources' : files('mount-tool.c'),
                'dependencies' : libmount,
        },
]

install_symlink('systemd-umount',
                pointing_to : 'systemd-mount',
                install_dir : bindir)
