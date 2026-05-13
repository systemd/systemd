# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-hwdb',
                'public' : true,
                'conditions' : ['ENABLE_HWDB'],
                'sources' : files('hwdb.c'),
                'link_with' : udev_link_with,
                'install_rpath' : udev_rpath,
                'install_tag' : 'hwdb',
        },
]
