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

generator= files('generate-strerrorname_np.sh')
libc_wrapper_sources += custom_target(
        input : generator,
        output : 'strerrorname_np.c',
        command : [env, 'bash', generator, cpp],
        capture : true)
