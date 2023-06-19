# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('HAVE_KMOD') != 1
        subdir_done()
endif

executables += [[
        {
                'name' : 'systemd-modules-load',
        },
        daemon_template + {
                'sources' : files('modules-load.c'),
                'dependencies' : [libkmod,
                                  userspace,
                                  versiondep],
        },
]]

meson.add_install_script('sh', '-c',
                         mkdir_p.format(modulesloaddir))
if install_sysconfdir
        meson.add_install_script('sh', '-c',
                                 mkdir_p.format(sysconfdir / 'modules-load.d'))
endif
