# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        generator_template + {
                'name' : 'systemd-modules-load-generator',
                'sources' : files('modules-load-generator.c'),
        },
]

install_emptydir(modulesloaddir)
if install_sysconfdir
        install_emptydir(sysconfdir / 'modules-load.d')
endif
