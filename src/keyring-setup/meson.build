# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-keyring-setup',
                'sources' : files('keyring-setup.c'),
                'dependencies' : [libkmod_cflags, libopenssl_cflags],
                'conditions' : ['HAVE_OPENSSL'],
        },
]
