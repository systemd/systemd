# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_cryptsetup_sources = files(
        'cryptsetup-fido2.h',
        'cryptsetup-keyfile.c',
        'cryptsetup-keyfile.h',
        'cryptsetup-pkcs11.h',
        'cryptsetup-tpm2.h',
        'cryptsetup.c')

if conf.get('HAVE_P11KIT') == 1
        systemd_cryptsetup_sources += files('cryptsetup-pkcs11.c')
endif

if conf.get('HAVE_LIBFIDO2') == 1
        systemd_cryptsetup_sources += files('cryptsetup-fido2.c')
endif

if conf.get('HAVE_TPM2') == 1
        systemd_cryptsetup_sources += files('cryptsetup-tpm2.c')
endif
