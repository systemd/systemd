# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_tpm2_plugin_sources = files('''
        systemd-tpm2-plugin.c
        cryptsetup-token.h
        luks2-tpm2.c
        luks2-tpm2.h
'''.split())

systemd_tpm2_plugin_version = '1.0.0'

systemd_tpm2_plugin_c_args = ['-fvisibility=default']

systemd_tpm2_plugin_static = static_library(
        'cryptsetup-token-systemd-tpm2_static',
        systemd_tpm2_plugin_sources,
        include_directories : includes,
        dependencies : libshared_deps + [libcryptsetup],
        c_args : systemd_tpm2_plugin_c_args)

systemd_tpm2_plugin_sym = files('cryptsetup-token.sym')
systemd_tpm2_plugin_sym_path = join_paths(meson.current_source_dir(), 'cryptsetup-token.sym')
