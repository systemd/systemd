# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        daemon_template + {
                'name' : 'systemd-fsck',
                'sources' : files('fsck.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]
