# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_REPART') != 1
        subdir_done()
endif

executables += [
        executable_template + {
                'name' : 'systemd-repart',
                'public' : true,
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
                'public' : true,
                'sources' : files('repart.c'),
                'c_args' : '-DSTANDALONE',
                'link_with' : [
                        libc_wrapper_static,
                        libbasic_static,
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
