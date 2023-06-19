# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_BLKID') != 1
        subdir_done()
endif

executables += [[
        {
                'name' : 'systemd-dissect',
                'public' : true
        },
        executable_template + {
                'sources' : files('dissect.c'),
                'dependencies' : [userspace,
                                  versiondep],
        },
]]

meson.add_install_script(meson_make_symlink,
                         bindir / 'systemd-dissect',
                         rootsbindir / 'mount.ddi')
