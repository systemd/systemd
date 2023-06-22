# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        daemon_template + {
                'name' : 'systemd-remount-fs',
                'sources' : files('remount-fs.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]
