# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        executable_template + {
                'name' : 'systemd-sysinstall',
                'public' : true,
                'conditions' : ['ENABLE_SYSINSTALL'],
                'sources' : files('sysinstall.c'),
        },
]

if conf.get('ENABLE_SYSINSTALL') == 1
        install_data('io.systemd.sysinstall.policy',
                     install_dir : polkitpolicydir)
endif
