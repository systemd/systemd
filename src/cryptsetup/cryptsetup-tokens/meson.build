# SPDX-License-Identifier: LGPL-2.1-or-later

lib_cryptsetup_token_common = static_library(
        'cryptsetup-token-common',
        'cryptsetup-token-util.c',
        include_directories : includes,
        implicit_include_directories : false,
        dependencies : userspace,
        link_with : libshared,
        build_by_default : false)

cryptsetup_token_systemd_empty_sources = files(
        'cryptsetup-token-systemd-empty.c'
)

cryptsetup_token_systemd_tpm2_sources = files(
        'cryptsetup-token-systemd-tpm2.c',
        'luks2-tpm2.c',
)

cryptsetup_token_systemd_fido2_sources = files(
        'cryptsetup-token-systemd-fido2.c',
        'luks2-fido2.c',
)

cryptsetup_token_systemd_pkcs11_sources = files(
        'cryptsetup-token-systemd-pkcs11.c',
        'luks2-pkcs11.c',
)

template = {
        'include_directories' : includes,
        'link_with' : [
                lib_cryptsetup_token_common,
                libshared,
        ],
        'version-script' : meson.current_source_dir() / 'cryptsetup-token.sym',
        'install_rpath' : pkglibdir,
        'install' : true,
        'install_dir' : libcryptsetup_plugins_dir,
}

modules += [
        template + {
                'name' : 'cryptsetup-token-systemd-empty',
                'conditions' : [
                        'HAVE_LIBCRYPTSETUP_PLUGINS',
                ],
                'sources' : cryptsetup_token_systemd_empty_sources,
                'dependencies' : [
                        libcryptsetup_cflags,
                ],
        },
        template + {
                'name' : 'cryptsetup-token-systemd-tpm2',
                'conditions' : [
                        'HAVE_LIBCRYPTSETUP_PLUGINS',
                        'HAVE_TPM2',
                ],
                'sources' : cryptsetup_token_systemd_tpm2_sources,
                'dependencies' : [
                        libcryptsetup_cflags,
                        tpm2_cflags,
                ],
        },
        template + {
                'name' : 'cryptsetup-token-systemd-fido2',
                'conditions' : [
                        'HAVE_LIBCRYPTSETUP_PLUGINS',
                        'HAVE_LIBFIDO2',
                ],
                'sources' : cryptsetup_token_systemd_fido2_sources,
                'dependencies' : [
                        libcryptsetup_cflags,
                        libfido2_cflags,
                ],
        },
        template + {
                'name' : 'cryptsetup-token-systemd-pkcs11',
                'conditions' : [
                        'HAVE_LIBCRYPTSETUP_PLUGINS',
                        'HAVE_P11KIT',
                ],
                'sources' : cryptsetup_token_systemd_pkcs11_sources,
                'dependencies' : [
                        libcryptsetup_cflags,
                        libp11kit_cflags,
                ],
        },
]
