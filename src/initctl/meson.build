# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-initctl',
                'conditions' : ['HAVE_SYSV_COMPAT'],
                'sources' : files('initctl.c'),
        },
]
