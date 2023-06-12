# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-hwdb',
                'conditions' : ['ENABLE_HWDB'],
                'public' : true,
                'sources' : files('hwdb.c'),
                'link_with' : udev_link_with,
                'install_rpath' : udev_rpath,
        },
]
