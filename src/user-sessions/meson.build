# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-user-sessions',
                'conditions' : ['HAVE_PAM'],
                'sources' : files('user-sessions.c'),
        },
]
