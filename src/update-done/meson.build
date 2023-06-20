# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        daemon_template + {
                'name' : 'systemd-update-done',
                'sources' : files('update-done.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]
