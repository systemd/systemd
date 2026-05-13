# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBMOUNT') != 1
        subdir_done()
endif

executables += [
        generator_template + {
                'name' : 'systemd-fstab-generator',
                'sources' : files('fstab-generator.c'),
                'dependencies' : libmount_cflags,
        },
]

assert(libexecdir / fs.name(systemgeneratordir) == systemgeneratordir)
install_symlink('systemd-sysroot-fstab-check',
                pointing_to : fs.name(systemgeneratordir) / 'systemd-fstab-generator',
                install_dir : libexecdir)
