# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-storage-block',
                'sources' : files('storage-block.c'),
                'extract' : files('storage-util.c')
        },
        libexec_template + {
                'name' : 'systemd-storage-fs',
                'sources' : files('storage-fs.c'),
                'objects' : ['systemd-storage-block'],
        },
        executable_template + {
                'name' : 'storagectl',
                'public' : true,
                'sources' : files('storagectl.c'),
                'objects' : ['systemd-storage-block'],
        },
]

install_symlink('mount.storage',
                pointing_to : sbin_to_bin + 'storagectl',
                install_dir : sbindir)

install_data('io.systemd.storage.policy',
             install_dir : polkitpolicydir)
