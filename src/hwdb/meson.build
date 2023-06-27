# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_HWDB') != 1
        subdir_done()
endif

executables += [
        executable_template + {
                'name' : 'systemd-hwdb',
                'public' : true,
                'sources' : files('hwdb.c'),
                'link_with' : udev_link_with,
                'install_rpath' : udev_rpath,
                'install_dir' : rootbindir,
        },
]
