# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBCRYPTSETUP_PLUGINS') == 1

cryptsetup_token_c_args = ['-fvisibility=hidden']

cryptsetup_token_sym = files('cryptsetup-token.sym')
cryptsetup_token_sym_path = meson.current_source_dir() / 'cryptsetup-token.sym'

if conf.get('HAVE_TPM2') == 1
        cryptsetup_token_systemd_tpm2_sources = files('''
                cryptsetup-token-systemd-tpm2.c
                cryptsetup-token.h
                cryptsetup-token-util.h
                cryptsetup-token-util.c
                luks2-tpm2.c
                luks2-tpm2.h
        '''.split())

        cryptsetup_token_systemd_tpm2_static = static_library(
                'cryptsetup-token-systemd-tpm2_static',
                cryptsetup_token_systemd_tpm2_sources,
                include_directories : includes,
                dependencies : libshared_deps + [libcryptsetup, versiondep],
                c_args : cryptsetup_token_c_args)
endif

if conf.get('HAVE_LIBFIDO2') == 1
        cryptsetup_token_systemd_fido2_sources = files('''
                cryptsetup-token-systemd-fido2.c
                cryptsetup-token.h
                cryptsetup-token-util.h
                cryptsetup-token-util.c
                luks2-fido2.c
                luks2-fido2.h
        '''.split())

        cryptsetup_token_systemd_fido2_static = static_library(
                'cryptsetup-token-systemd-fido2_static',
                cryptsetup_token_systemd_fido2_sources,
                include_directories : includes,
                dependencies : libshared_deps + [libcryptsetup, versiondep],
                c_args : cryptsetup_token_c_args)
endif

if conf.get('HAVE_P11KIT') == 1
        cryptsetup_token_systemd_pkcs11_sources = files('''
                cryptsetup-token-systemd-pkcs11.c
                cryptsetup-token.h
                cryptsetup-token-util.h
                cryptsetup-token-util.c
                luks2-pkcs11.c
                luks2-pkcs11.h
        '''.split())

        cryptsetup_token_systemd_pkcs11_static = static_library(
                'cryptsetup-token-systemd-pkcs11_static',
                cryptsetup_token_systemd_pkcs11_sources,
                include_directories : includes,
                dependencies : libshared_deps + [libcryptsetup, versiondep],
                c_args : cryptsetup_token_c_args)
endif

endif
