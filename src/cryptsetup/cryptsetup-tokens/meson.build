# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBCRYPTSETUP_PLUGINS') != 1
        subdir_done()
endif

cryptsetup_token_sym = files('cryptsetup-token.sym')
cryptsetup_token_sym_path = meson.current_source_dir() / 'cryptsetup-token.sym'

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

default_dep = [
        libcryptsetup,
        userspace,
        versiondep
]

template = {
        'include_directories' : includes,
        'link_args' : ['-shared',
                       '-Wl,--version-script=' + cryptsetup_token_sym_path],
        'link_with' : [lib_cryptsetup_token_common,
                       libshared],
        'link_depends' : cryptsetup_token_sym,
        'install_rpath' : pkglibdir,
        'install' : true,
        'install_dir' : libcryptsetup_plugins_dir,
}

libraries += [
        [
                {
                        'name' : 'cryptsetup-token-systemd-tpm2',
                        'conditions' : ['HAVE_TPM2'],
                },
                template + {
                        'sources' : cryptsetup_token_systemd_tpm2_sources,
                        'dependencies' : default_dep + [tpm2],
                },
        ],
        [
                {
                        'name' : 'cryptsetup-token-systemd-fido2',
                        'conditions' : ['HAVE_LIBFIDO2'],
                },
                template + {
                        'sources' : cryptsetup_token_systemd_fido2_sources,
                        'dependencies' : default_dep + [libfido2],
                },
        ],
        [
                {
                        'name' : 'cryptsetup-token-systemd-pkcs11',
                        'conditions' : ['HAVE_P11KIT'],
                },
                template + {
                        'sources' : cryptsetup_token_systemd_pkcs11_sources,
                        'dependencies' : default_dep + [libp11kit],
                },
        ],
]
