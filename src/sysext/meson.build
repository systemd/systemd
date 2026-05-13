# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-sysext',
                'public' : true,
                'conditions' : ['ENABLE_SYSEXT'],
                'sources' : files('sysext.c'),
                'dependencies' : [
                        libblkid_cflags,
                        libcryptsetup_cflags,
                        libmount_cflags,
                ],
        },
]

if conf.get('ENABLE_SYSEXT') == 1
        install_symlink('systemd-confext',
                        pointing_to : 'systemd-sysext',
                        install_dir : bindir)

        install_data('io.systemd.sysext.policy',
                install_dir : polkitpolicydir)
endif
