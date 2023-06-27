# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_tmpfiles_sources = files(
        'tmpfiles.c',
        'offline-passwd.c',
)

executables += [
        executable_template + {
                'name' : 'systemd-tmpfiles',
                'public' : true,
                'conditions' : ['ENABLE_TMPFILES'],
                'sources' : systemd_tmpfiles_sources,
                'dependencies' : libacl,
                'install_dir' : rootbindir,
        },
        executable_template + {
                'name' : 'systemd-tmpfiles.standalone',
                'public' : have_standalone_binaries,
                'conditions' : ['ENABLE_TMPFILES'],
                'sources' : systemd_tmpfiles_sources,
                'c_args' : '-DSTANDALONE',
                'link_with' : [libshared_static,
                               libbasic,
                               libbasic_gcrypt,
                               libsystemd_static],
                'dependencies' : libacl,
                'build_by_default' : have_standalone_binaries,
                'install' : have_standalone_binaries,
                'install_dir' : rootbindir,
        },
        test_template + {
                'sources' : files(
                        'test-offline-passwd.c',
                        'offline-passwd.c',
                ),
        },
]
