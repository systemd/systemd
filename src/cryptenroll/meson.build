# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBCRYPTSETUP') != 1
        subdir_done()
endif

systemd_cryptenroll_sources = files(
        'cryptenroll-list.c',
        'cryptenroll-password.c',
        'cryptenroll-recovery.c',
        'cryptenroll-wipe.c',
        'cryptenroll.c',
)

if conf.get('HAVE_P11KIT') == 1 and conf.get('HAVE_OPENSSL') == 1
        systemd_cryptenroll_sources += files('cryptenroll-pkcs11.c')
endif

if conf.get('HAVE_LIBFIDO2') == 1
        systemd_cryptenroll_sources += files('cryptenroll-fido2.c')
endif

if conf.get('HAVE_TPM2') == 1
        systemd_cryptenroll_sources += files('cryptenroll-tpm2.c')
endif

executables += [
        executable_template + {
                'name' : 'systemd-cryptenroll',
                'public' : true,
                'sources' : systemd_cryptenroll_sources,
                'dependencies' : [
                        libcryptsetup,
                        libdl,
                        libopenssl,
                        libp11kit_cflags,
                ],
        },
]
