# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-sysext',
                'conditions' : ['ENABLE_SYSEXT'],
                'public' : true,
                'sources' : files('sysext.c'),
        },
]

if conf.get('ENABLE_SYSEXT') == 1
        install_symlink('systemd-confext',
                        pointing_to : 'systemd-sysext',
                        install_dir : bindir)
endif
