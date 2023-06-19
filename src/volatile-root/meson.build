# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_INITRD') != 1
        subdir_done()
endif

executables += [
        daemon_template + {
                'name' : 'systemd-volatile-root',
                'sources' : files('volatile-root.c'),
        },
]
