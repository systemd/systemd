# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_SYSEXT') != 1
        subdir_done()
endif

executables += [
        executable_template + {
                'name' : 'systemd-sysext',
                'public' : true,
                'sources' : files('sysext.c'),
        },
]

install_symlink('systemd-confext',
                pointing_to : 'systemd-sysext',
                install_dir : bindir)
