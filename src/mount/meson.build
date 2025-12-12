# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_LIBMOUNT') != 1
        subdir_done()
endif

executables += [
        executable_template + {
                'name' : 'systemd-mount',
                'public' : true,
                'sources' : files('mount-tool.c'),
                'dependencies' : libmount_cflags,
        },
]

install_symlink('systemd-umount',
                pointing_to : 'systemd-mount',
                install_dir : bindir)
