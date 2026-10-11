# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBMOUNT') != 1
        subdir_done()
endif

executables += [
        generator_template + {
                'name' : 'systemd-fstab-generator',
                'sources' : files('fstab-generator.c'),
                'dependencies' : libmount_cflags,
                'symlinks' : [
                        { 'name' : 'systemd-sysroot-fstab-check', 'install_dir' : libexecdir },
                ],
        },
]
