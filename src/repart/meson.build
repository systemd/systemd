# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_REPART') != 1
        subdir_done()
endif

executables += [
        executable_template + {
                'name' : 'systemd-repart',
                'public' : true,
                'extract' : files(
                        'repart.c',
                        'iso9660.c',
                ),
                'dependencies' : [
                        libblkid_cflags,
                        libfdisk_cflags,
                        libmount_cflags,
                        libopenssl_cflags,
                        threads,
                ],
        },
        executable_template + {
                'name' : 'systemd-repart.standalone',
                'public' : true,
                'objects' : ['systemd-repart'],
                'link_with' : [
                        libc_wrapper_static,
                        libbasic_static,
                        libshared_static,
                        libsystemd_static,
                ],
                'dependencies' : [
                        libblkid_cflags,
                        libfdisk_cflags,
                        libmount_cflags,
                        libopenssl_cflags,
                        threads,
                ],
        },
]

install_data('definitions/confext.repart.d/10-root.conf',             install_dir : repartdefinitionsdir / 'confext.repart.d')
install_data('definitions/confext.repart.d/20-root-verity.conf',      install_dir : repartdefinitionsdir / 'confext.repart.d')
install_data('definitions/confext.repart.d/30-root-verity-sig.conf',  install_dir : repartdefinitionsdir / 'confext.repart.d')
install_data('definitions/portable.repart.d/10-root.conf',            install_dir : repartdefinitionsdir / 'portable.repart.d')
install_data('definitions/portable.repart.d/20-root-verity.conf',     install_dir : repartdefinitionsdir / 'portable.repart.d')
install_data('definitions/portable.repart.d/30-root-verity-sig.conf', install_dir : repartdefinitionsdir / 'portable.repart.d')
install_data('definitions/sysext.repart.d/10-root.conf',              install_dir : repartdefinitionsdir / 'sysext.repart.d')
install_data('definitions/sysext.repart.d/20-root-verity.conf',       install_dir : repartdefinitionsdir / 'sysext.repart.d')
install_data('definitions/sysext.repart.d/30-root-verity-sig.conf',   install_dir : repartdefinitionsdir / 'sysext.repart.d')
