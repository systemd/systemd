# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_FIRSTBOOT') != 1
        subdir_done()
endif

executables += [[
        {
                'name' : 'systemd-firstboot',
                'public' : true,
        },
        executable_template + {
                'sources' : files('firstboot.c'),
                'dependencies' : [libcrypt,
                                  userspace,
                                  versiondep],
                'install_dir' : rootbindir,
        },
]]
