# SPDX-License-Identifier: LGPL-2.1-or-later

subdir('cryptsetup-tokens')

systemd_cryptsetup_sources = files(
        'cryptsetup-keyfile.c',
        'cryptsetup.c',
)

if conf.get('HAVE_P11KIT') == 1
        systemd_cryptsetup_sources += files('cryptsetup-pkcs11.c')
endif

if conf.get('HAVE_TPM2') == 1
        systemd_cryptsetup_sources += files('cryptsetup-tpm2.c')
endif

executables += [
        libexec_template + {
                'name' : 'systemd-cryptsetup',
                'conditions' : ['HAVE_LIBCRYPTSETUP'],
                'sources' : systemd_cryptsetup_sources,
                'dependencies' : [
                        libcryptsetup,
                        libopenssl,
                        libp11kit,
                ],
        },
        generator_template + {
                'name' : 'systemd-cryptsetup-generator',
                'conditions' : ['HAVE_LIBCRYPTSETUP'],
                'sources' : files('cryptsetup-generator.c'),
        },
]
