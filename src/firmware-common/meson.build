# SPDX-License-Identifier: LGPL-2.1-or-later

firmware_common_path = meson.current_source_dir()

firmware_common_headers = files(
        'efi-loader-features.h',
        'macro-common.h',
        'string-util-common.h',
        'type.h')

sources = '''
        string-util-common.c
'''.split()

# for sd-boot
firmware_common_source_paths = []
foreach s : sources
        firmware_common_source_paths += join_paths(meson.current_source_dir(), s)
endforeach

# for libbasic
firmware_common_sources = files(sources) + firmware_common_headers
