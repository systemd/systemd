# SPDX-License-Identifier: LGPL-2.1-or-later

cryptsetup_token_sym = files('cryptsetup-token.sym')
cryptsetup_token_sym_path = meson.current_source_dir() / 'cryptsetup-token.sym'

lib_cryptsetup_token_common = static_library(
        'cryptsetup-token-common',
        'cryptsetup-token.h',
        'cryptsetup-token-util.h',
        'cryptsetup-token-util.c',
        include_directories : includes,
        link_with : libshared,
        build_by_default : false)

cryptsetup_token_systemd_tpm2_sources = files(
        'cryptsetup-token-systemd-tpm2.c',
        'luks2-tpm2.c',
        'luks2-tpm2.h')

cryptsetup_token_systemd_fido2_sources = files(
        'cryptsetup-token-systemd-fido2.c',
        'luks2-fido2.c',
        'luks2-fido2.h')

cryptsetup_token_systemd_pkcs11_sources = files(
        'cryptsetup-token-systemd-pkcs11.c',
        'luks2-pkcs11.c',
        'luks2-pkcs11.h')
