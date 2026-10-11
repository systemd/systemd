# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-storage-block',
                'sources' : files('storage-block.c'),
        },
        libexec_template + {
                'name' : 'systemd-storage-fs',
                'sources' : files('storage-fs.c'),
        },
        executable_template + {
                'name' : 'storagectl',
                'public' : true,
                'sources' : files('storagectl.c'),
                'symlinks' : [
                        { 'name' : 'mount.storage', 'install_dir' : sbindir },
                ],
        },
]

install_data('io.systemd.storage.policy',
             install_dir : polkitpolicydir)
