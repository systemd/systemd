# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_SYSUSERS') != 1
        subdir_done()
endif

executables += [
        executable_template + {
                'name' : 'systemd-sysusers',
                'public' : true,
                'sources' : files('sysusers.c'),
                'dependencies' : libaudit,
        },
        executable_template + {
                'name' : 'systemd-sysusers.standalone',
                'public' : have_standalone_binaries,
                'sources' : files('sysusers.c'),
                'c_args' : '-DSTANDALONE',
                'link_with' : [
                        libbasic_static,
                        libshared_static,
                        libsystemd_static,
                ],
                'dependencies' : libaudit,
                'build_by_default' : have_standalone_binaries,
                'install' : have_standalone_binaries,
        },
]
