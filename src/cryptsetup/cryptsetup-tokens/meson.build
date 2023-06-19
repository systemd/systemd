# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBCRYPTSETUP_PLUGINS') != 1
        subdir_done()
endif

lib_cryptsetup_token_common = static_library(
        'cryptsetup-token-common',
        'cryptsetup-token-util.c',
        include_directories : includes,
        dependencies : userspace,
        link_with : libshared,
        build_by_default : false)

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

common_dep = [
        libcryptsetup,
        userspace,
        versiondep
]

template = {
        'include_directories' : includes,
        'link_with' : [lib_cryptsetup_token_common,
                       libshared],
        'link_depends' : files('cryptsetup-token.sym'),
        'install_rpath' : rootpkglibdir,
        'install' : true,
        'install_dir' : libcryptsetup_plugins_dir,
}

modules += [
        [
                {
                        'name' : 'cryptsetup-token-systemd-tpm2',
                        'conditions' : ['HAVE_TPM2'],
                },
                template + {
                        'sources' : cryptsetup_token_systemd_tpm2_sources,
                        'dependencies' : common_dep + [tpm2],
                },
        ],
        [
                {
                        'name' : 'cryptsetup-token-systemd-fido2',
                        'conditions' : ['HAVE_LIBFIDO2'],
                },
                template + {
                        'sources' : cryptsetup_token_systemd_fido2_sources,
                        'dependencies' : common_dep + [libfido2],
                },
        ],
        [
                {
                        'name' : 'cryptsetup-token-systemd-pkcs11',
                        'conditions' : ['HAVE_P11KIT'],
                },
                template + {
                        'sources' : cryptsetup_token_systemd_pkcs11_sources,
                        'dependencies' : common_dep + [libp11kit],
                },
        ],
]
