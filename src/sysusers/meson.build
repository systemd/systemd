# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-sysusers',
                'public' : true,
                'conditions' : ['ENABLE_SYSUSERS'],
                'sources' : files('sysusers.c'),
                'install_dir' : rootbindir,
        },
        executable_template + {
                'name' : 'systemd-sysusers.standalone',
                'public' : have_standalone_binaries,
                'conditions' : ['ENABLE_SYSUSERS'],
                'sources' : files('sysusers.c'),
                'c_args' : '-DSTANDALONE',
                'link_with' : [libshared_static,
                               libbasic,
                               libbasic_gcrypt,
                               libsystemd_static],
                'build_by_default' : have_standalone_binaries,
                'install' : have_standalone_binaries,
                'install_dir' : rootbindir,
        },
]
