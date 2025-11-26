# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBMOUNT') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-remount-fs',
                'sources' : files('remount-fs.c'),
                'dependencies' : libmount_cflags,
        },
]
