# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-firstboot',
                'public' : true,
                'conditions' : ['ENABLE_FIRSTBOOT'],
                'sources' : files('firstboot.c'),
                'dependencies' : libcrypt,
        },
]
