# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-measure',
                'conditions' : [
                        'HAVE_BLKID',
                        'HAVE_OPENSSL',
                        'HAVE_TPM2',
                ],
                'sources' : files('measure.c'),
                'dependencies' : libopenssl,
        },
        libexec_template + {
                'name' : 'systemd-sbsign',
                'conditions' : [
                        'HAVE_OPENSSL',
                ],
                'sources' : files('sbsign.c'),
                'dependencies' : libopenssl,
        },
]
