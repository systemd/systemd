# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_ENVIRONMENT_D') != 1
        subdir_done()
endif

executables += [
        executable_template + {
                'name' : '30-systemd-environment-d-generator',
                'sources' : files('environment-d-generator.c'),
                'install_dir' : userenvgeneratordir,
        },
]

meson.add_install_script(meson_make_symlink,
                         sysconfdir / 'environment',
                         environmentdir / '99-environment.conf')
