# SPDX-License-Identifier: LGPL-2.1-or-later

cryptsetup_token_systemd_tpm2_sources = files('''
        cryptsetup-token-systemd-tpm2.c
        cryptsetup-token.h
        luks2-tpm2.c
        luks2-tpm2.h
'''.split())

# systemd_tpm2_plugin_version = '1.0.0'

cryptsetup_token_systemd_tpm2_c_args = ['-fvisibility=hidden']

cryptsetup_token_systemd_tpm2_static = static_library(
        'cryptsetup-token-systemd-tpm2_static',
        cryptsetup_token_systemd_tpm2_sources,
        include_directories : includes,
        dependencies : libshared_deps + [libcryptsetup],
        c_args : cryptsetup_token_systemd_tpm2_c_args)

cryptsetup_token_systemd_tpm2_sym = files('cryptsetup-token.sym')
cryptsetup_token_systemd_tpm2_sym_path = join_paths(meson.current_source_dir(), 'cryptsetup-token.sym')
