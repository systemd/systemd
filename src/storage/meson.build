# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_STORAGE') != 1
        subdir_done()
endif

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
                'sources' : files('storagectl.c'),
                'symlinks' : [
                        { 'name' : 'mount.storage', 'install_dir' : sbindir },
                ],
        },
]

install_data('io.systemd.storage.policy',
             install_dir : polkitpolicydir)
