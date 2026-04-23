# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-volume-block',
                'sources' : files('volume-block.c', 'volume-util.c'),
        },
]

install_data('io.systemd.volumes.policy',
             install_dir : polkitpolicydir)
