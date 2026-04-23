# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-storage-block',
                'sources' : files('storage-block.c'),
                'extract' : files('storage-util.c')
        },
        executable_template + {
                'name' : 'systemd-storage-fs',
                'sources' : files('storage-fs.c'),
                'objects' : ['systemd-storage-block'],
        },
]

install_data('io.systemd.storage.policy',
             install_dir : polkitpolicydir)
