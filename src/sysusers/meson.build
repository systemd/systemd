# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_SYSUSERS') != 1
        subdir_done()
endif

executables += [
        executable_template + {
                'name' : 'systemd-sysusers',
                'public' : true,
                'export' : files('sysusers.c'),
                'dependencies' : libaudit_cflags,
                'install' : have_standalone_binaries ? 'both' : 'yes',
        },
]
