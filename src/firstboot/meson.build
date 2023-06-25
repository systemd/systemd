# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-firstboot',
                'conditions' : ['ENABLE_FIRSTBOOT'],
                'public' : true,
                'sources' : files('firstboot.c'),
                'dependencies' : libcrypt,
                'install_dir' : rootbindir,
        },
]
