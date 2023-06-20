# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_RFKILL') != 1
        subdir_done()
endif

executables += [
        daemon_template + {
                'name' : 'systemd-rfkill',
                'sources' : files('rfkill.c'),
        },
]
