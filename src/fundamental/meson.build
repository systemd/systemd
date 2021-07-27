# SPDX-License-Identifier: LGPL-2.1-or-later

fundamental_path = meson.current_source_dir()

fundamental_headers = files(
        'efi-loader-features.h',
        'macro-fundamental.h',
        'string-util-fundamental.h',
        'type.h')

sources = '''
        string-util-fundamental.c
'''.split()

# for sd-boot
fundamental_source_paths = []
foreach source : sources
        fundamental_source_paths += meson.current_source_dir() / source
endforeach

# for libbasic
fundamental_sources = files(sources) + fundamental_headers
