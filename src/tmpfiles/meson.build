# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_TMPFILES') != 1
        subdir_done()
endif

offline_passwd_c = files('offline-passwd.c')

executables += [
        executable_template + {
                'name' : 'systemd-tmpfiles',
                'public' : true,
                'export' : files('tmpfiles.c') +
                            offline_passwd_c,
                'dependencies' : [
                        libacl_cflags,
                        libselinux_cflags,
                ],
                'install' : have_standalone_binaries ? 'both' : 'yes',
        },
        test_template + {
                'sources' : files('test-offline-passwd.c') +
                            offline_passwd_c,
        },
]
