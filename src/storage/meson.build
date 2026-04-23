# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-storage-block',
                'sources' : files('storage-block.c', 'storage-util.c'),
        },
]

install_data('io.systemd.storage.policy',
             install_dir : polkitpolicydir)
