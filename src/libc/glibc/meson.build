# SPDX-License-Identifier: LGPL-2.1-or-later

if get_option('libc') != 'glibc'
        subdir_done()
endif

libc_wrapper_sources += files(
        'stdio.c',
        'stdlib.c',
)
