# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-sbsign',
                'conditions' : [
                        'HAVE_OPENSSL',
                ],
                'sources' : files(
                        'sbsign.c',
                        'authenticode.c',
                ),
                'dependencies' : libopenssl_cflags,
        },
]
