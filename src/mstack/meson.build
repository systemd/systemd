# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-mstack',
                'public' : true,
                'sources' : files('mstack-tool.c'),
        },
]

install_symlink('mount.mstack',
                pointing_to : sbin_to_bin + 'systemd-mstack',
                install_dir : sbindir)
