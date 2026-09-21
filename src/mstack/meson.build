# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-mstack',
                'public' : true,
                'sources' : files('mstack-tool.c'),
                'symlinks' : [
                        { 'name' : 'mount.mstack', 'install_dir' : sbindir },
                ],
        },
]
