# SPDX-License-Identifier: LGPL-2.1-or-later

if get_option('b_coverage')
        userspace_c_args += ['-include', meson.current_source_dir() / 'coverage.h']
        userspace_sources += files('coverage.h')
endif
