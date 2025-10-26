# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBCRYPTSETUP') != 1
        subdir_done()
endif

systemd_cryptenroll_sources = files(
        'cryptenroll.c',
        'cryptenroll-fido2.c',
        'cryptenroll-list.c',
        'cryptenroll-password.c',
        'cryptenroll-pkcs11.c',
        'cryptenroll-recovery.c',
        'cryptenroll-tpm2.c',
        'cryptenroll-wipe.c',
)

executables += [
        executable_template + {
                'name' : 'systemd-cryptenroll',
                'public' : true,
                'sources' : systemd_cryptenroll_sources,
                'dependencies' : [
                        libcryptsetup_cflags,
                        libdl,
                        libopenssl,
                        libp11kit_cflags,
                ],
        },
]
