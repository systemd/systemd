# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-hwdb',
                'public' : true,
                'conditions' : ['ENABLE_HWDB'],
                'sources' : files('hwdb.c'),
                'install' : get_option('link-udev-shared') ? 'yes' : 'static',
                'install_tag' : 'hwdb',
        },
]
