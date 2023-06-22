# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_SYSV_COMPAT') != 1
        subdir_done()
endif

executables += [
        daemon_template + {
                'name' : 'systemd-initctl',
                'sources' : files('initctl.c'),
        },
]
