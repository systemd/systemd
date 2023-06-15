# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : '30-systemd-environment-d-generator',
                'conditions' : ['ENABLE_ENVIRONMENT_D'],
                'sources' : files('environment-d-generator.c'),
                'install_dir' : userenvgeneratordir,
        },
]

if conf.get('ENABLE_ENVIRONMENT_D') == 1
        # install_symlink() does not support broken symlink, and /etc/environment is not managed by us, thus
        # may not exist. Hence, we need to create it by using the custom install script here.
        install_emptydir(environmentdir)
        meson.add_install_script(sh, '-c',
                                 ln_s.format(sysconfdir / 'environment',
                                             environmentdir / '99-environment.conf'))
endif
