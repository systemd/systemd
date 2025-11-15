# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_TMPFILES') != 1
        subdir_done()
endif

systemd_tmpfiles_sources = files(
        'tmpfiles.c',
)
executables += [
        executable_template + {
                'name' : 'systemd-tmpfiles',
                'public' : true,
                'sources' : systemd_tmpfiles_sources,
                'dependencies' : libacl_cflags,
        },
        executable_template + {
                'name' : 'systemd-tmpfiles.standalone',
                'public' : true,
                'sources' : systemd_tmpfiles_sources,
                'c_args' : '-DSTANDALONE',
                'link_with' : [
                        libc_wrapper_static,
                        libbasic_static,
                        libshared_static,
                        libsystemd_static,
                ],
                'dependencies' : libacl_cflags,
        },
]
