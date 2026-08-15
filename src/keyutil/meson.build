# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-keyutil',
                'conditions' : [
                        'HAVE_OPENSSL',
                ],
                'sources' : files('keyutil.c'),
                'dependencies' : libopenssl_cflags,
        },
]
