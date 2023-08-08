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
        install_emptydir(environmentdir)
        meson.add_install_script(sh, '-c',
                                 ln_s.format(sysconfdir / 'environment',
                                             environmentdir / '99-environment.conf'))
endif
