# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-pcrlock',
                'conditions' : [
                        'HAVE_OPENSSL',
                        'HAVE_TPM2'
                ],
                'sources' : files(
                        'pcrlock.c',
                        'pcrlock-firmware.c',
                        'pehash.c',
                ),
                'dependencies' : [
                        libm,
                        libopenssl,
                        tpm2,
                ],
        },
]
