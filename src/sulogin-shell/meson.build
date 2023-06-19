# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        daemon_template + {
                'name' : 'systemd-sulogin-shell',
                'sources' : files('sulogin-shell.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]
