# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-volume-block',
                'sources' : files('volume-block.c'),
                'extract' : files('volume-util.c')
        },
        executable_template + {
                'name' : 'systemd-volume-fs',
                'sources' : files('volume-fs.c'),
                'objects' : ['systemd-volume-block'],
        },
        executable_template + {
                'name' : 'volumectl',
                'public' : true,
                'sources' : files('volumectl.c'),
                'objects' : ['systemd-volume-block'],
        },
]

install_symlink('mount.volume',
                pointing_to : sbin_to_bin + 'volumectl',
                install_dir : sbindir)
