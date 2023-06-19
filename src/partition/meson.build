# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        [
                {
                        'name' : 'systemd-growfs'
                },
                daemon_template + {
                        'sources' : files('growfs.c'),
                        'dependencies' : [userspace,
                                          versiondep],
                },
        ],
        [
                {
                        'name' : 'systemd-makefs',
                },
                daemon_template + {
                        'sources' : files('makefs.c'),
                        'dependencies' : [userspace,
                                          versiondep],
                },
        ],
        [
                {
                        'name' : 'systemd-repart',
                        'public' : true,
                        'conditions' : ['ENABLE_REPART'],
                },
                executable_template + {
                        'sources' : files('repart.c'),
                        'link_with' : [libshared,
                                       libshared_fdisk],
                        'dependencies' : [libblkid,
                                          libfdisk,
                                          libopenssl,
                                          threads,
                                          userspace,
                                          versiondep],
                        'install_dir' : rootbindir,
                },
        ],
        [
                {
                        'name' : 'systemd-repart.standalone',
                        'public' : have_standalone_binaries,
                        'conditions' : ['ENABLE_REPART'],
                },
                executable_template + {
                        'sources' : files('repart.c'),
                        'c_args' : '-DSTANDALONE',
                        'link_with' : [libshared_static,
                                       libbasic,
                                       libbasic_gcrypt,
                                       libsystemd_static,
                                       libshared_fdisk],
                        'dependencies' : [libblkid,
                                          libfdisk,
                                          libopenssl,
                                          threads,
                                          userspace,
                                          versiondep],
                        'build_by_default' : have_standalone_binaries,
                        'install' : have_standalone_binaries,
                        'install_dir' : rootbindir,
                },
        ],
]
