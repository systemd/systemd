# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-tpm2-setup',
                'sources' : files('tpm2-setup.c'),
                'conditions' : [
                        'ENABLE_BOOTLOADER',
                        'HAVE_OPENSSL',
                        'HAVE_TPM2',
                ],
                'dependencies' : [
                        libopenssl,
                ],
        },
        libexec_template + {
                'name' : 'systemd-tpm2-clear',
                'sources' : files('tpm2-clear.c'),
                'conditions' : [
                        'ENABLE_BOOTLOADER',
                        'HAVE_OPENSSL',
                        'HAVE_TPM2',
                ],
        },
        generator_template + {
                'name' : 'systemd-tpm2-generator',
                'sources' : files('tpm2-generator.c'),
        },

]
