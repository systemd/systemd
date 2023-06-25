# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-growfs',
                'sources' : files('growfs.c'),
        },
        libexec_template + {
                'name' : 'systemd-makefs',
                'sources' : files('makefs.c'),
        },
        executable_template + {
                'name' : 'systemd-repart',
                'public' : true,
                'conditions' : ['ENABLE_REPART'],
                'sources' : files('repart.c'),
                'link_with' : [
                        libshared,
                        libshared_fdisk,
                ],
                'dependencies' : [
                        libblkid,
                        libfdisk,
                        libopenssl,
                        threads,
                ],
        },
        executable_template + {
                'name' : 'systemd-repart.standalone',
                'public' : have_standalone_binaries,
                'conditions' : ['ENABLE_REPART'],
                'sources' : files('repart.c'),
                'c_args' : '-DSTANDALONE',
                'link_with' : [
                        libbasic,
                        libbasic_gcrypt,
                        libshared_fdisk,
                        libshared_static,
                        libsystemd_static,
                ],
                'dependencies' : [
                        libblkid,
                        libfdisk,
                        libopenssl,
                        threads,
                ],
                'build_by_default' : have_standalone_binaries,
                'install' : have_standalone_binaries,
        },
]
