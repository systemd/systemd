# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        daemon_template + {
                'name' : 'systemd-sysctl',
                'public' : true,
                'sources' : files('sysctl.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]
