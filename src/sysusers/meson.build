# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_SYSUSERS') != 1
        subdir_done()
endif

executables += [
        executable_template + {
                'name' : 'systemd-sysusers',
                'export' : files('sysusers.c'),
                'dependencies' : libaudit_cflags,
        },
]
