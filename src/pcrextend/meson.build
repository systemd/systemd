# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-pcrextend',
                'conditions' : [
                        'HAVE_BLKID',
                        'ENABLE_BOOTLOADER',
                        'HAVE_OPENSSL',
                        'HAVE_TPM2',
                ],
                'sources' : files('pcrextend.c'),
                'dependencies' : [
                        libopenssl_cflags,
                        tpm2,
                ],
        },
]
