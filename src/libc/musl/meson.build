# SPDX-License-Identifier: LGPL-2.1-or-later

if get_option('libc') != 'musl'
        subdir_done()
endif

libc_wrapper_sources += files(
        'printf.c',
        'stdio.c',
        'stdlib.c',
        'string.c',
        'time.c',
        'unistd.c',
)
