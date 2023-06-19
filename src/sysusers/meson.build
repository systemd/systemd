# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        [
                {
                        'name' : 'systemd-sysusers',
                        'public' : true,
                        'conditions' : ['ENABLE_SYSUSERS'],
                },
                executable_template + {
                        'sources' : files('sysusers.c'),
                        'dependencies' : [userspace,
                                          versiondep],
                        'install_dir' : rootbindir,
                },
        ],
        [
                {
                        'name' : 'systemd-sysusers.standalone',
                        'public' : have_standalone_binaries,
                        'conditions' : ['ENABLE_SYSUSERS'],
                },
                executable_template + {
                        'sources' : files('sysusers.c'),
                        'c_args' : '-DSTANDALONE',
                        'link_with' : [libshared_static,
                                       libbasic,
                                       libbasic_gcrypt,
                                       libsystemd_static],
                        'dependencies' : [userspace,
                                          versiondep],
                        'build_by_default' : have_standalone_binaries,
                        'install' : have_standalone_binaries,
                        'install_dir' : rootbindir,
                },
        ],
]
