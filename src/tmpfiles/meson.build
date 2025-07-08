# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_TMPFILES') != 1
        subdir_done()
endif

systemd_tmpfiles_sources = files(
        'tmpfiles.c',
)
systemd_tmpfiles_extract_sources = files(
        'offline-passwd.c',
)

executables += [
        executable_template + {
                'name' : 'systemd-tmpfiles',
                'public' : true,
                'sources' : systemd_tmpfiles_sources + systemd_tmpfiles_extract_sources,
                'extract' : systemd_tmpfiles_extract_sources,
                'dependencies' : libacl,
        },
        executable_template + {
                'name' : 'systemd-tmpfiles.standalone',
                'public' : true,
                'sources' : systemd_tmpfiles_sources + systemd_tmpfiles_extract_sources,
                'c_args' : '-DSTANDALONE',
                'link_with' : [
                        libc_wrapper_static,
                        libbasic_static,
                        libshared_static,
                        libsystemd_static,
                ],
                'dependencies' : libacl,
        },
        test_template + {
                'sources' : files('test-offline-passwd.c'),
                'objects' : ['systemd-tmpfiles'],
        },
]
