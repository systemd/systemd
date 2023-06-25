# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-sysusers',
                'public' : true,
                'conditions' : ['ENABLE_SYSUSERS'],
                'sources' : files('sysusers.c'),
        },
        executable_template + {
                'name' : 'systemd-sysusers.standalone',
                'public' : have_standalone_binaries,
                'conditions' : ['ENABLE_SYSUSERS'],
                'sources' : files('sysusers.c'),
                'c_args' : '-DSTANDALONE',
                'link_with' : [
                        libbasic,
                        libbasic_gcrypt,
                        libshared_static,
                        libsystemd_static,
                ],
                'build_by_default' : have_standalone_binaries,
                'install' : have_standalone_binaries,
        },
]
