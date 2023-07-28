# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_FIRSTBOOT') != 1
        subdir_done()
endif

executables += [
        executable_template + {
                'name' : 'systemd-firstboot',
                'public' : true,
                'sources' : files('firstboot.c'),
                'dependencies' : libcrypt,
        },
]
