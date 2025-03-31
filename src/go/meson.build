# SPDX-License-Identifier: LGPL-2.1-or-later

libgo = custom_target(
        'libgo',
        output: 'go_library.a',
        build_always_stale: true,
        command: ['go', 'build',
                '-C', meson.current_source_dir(),
                '-buildmode=c-archive', '-o', meson.current_build_dir() / 'go_library.a' , '.'],
)

libgo_dep = declare_dependency (sources: libgo)
