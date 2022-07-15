# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_cryptenroll_sources = files(
        'cryptenroll-fido2.h',
        'cryptenroll-list.c',
        'cryptenroll-list.h',
        'cryptenroll-password.c',
        'cryptenroll-password.h',
        'cryptenroll-pkcs11.h',
        'cryptenroll-recovery.c',
        'cryptenroll-recovery.h',
        'cryptenroll-tpm2.h',
        'cryptenroll-wipe.c',
        'cryptenroll-wipe.h',
        'cryptenroll.c',
        'cryptenroll.h')

if conf.get('HAVE_P11KIT') == 1 and conf.get('HAVE_OPENSSL') == 1
        systemd_cryptenroll_sources += files('cryptenroll-pkcs11.c')
endif

if conf.get('HAVE_LIBFIDO2') == 1
        systemd_cryptenroll_sources += files('cryptenroll-fido2.c')
endif

if conf.get('HAVE_TPM2') == 1
        systemd_cryptenroll_sources += files('cryptenroll-tpm2.c')
endif
