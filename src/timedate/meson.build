# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-timedated',
                'dbus' : true,
                'conditions' : ['ENABLE_TIMEDATED'],
                'sources' : files(
                        'timedated.c',
                        'hwclock-util.c',
                ),

        },
        executable_template + {
                'name' : 'timedatectl',
                'public' : true,
                'conditions' : ['ENABLE_TIMEDATECTL'],
                'sources' : files('timedatectl.c'),
                'dependencies' : libm,
        },
]

if conf.get('ENABLE_TIMEDATED') == 1
        install_data('org.freedesktop.timedate1.conf',
                     install_dir : dbuspolicydir)
        install_data('org.freedesktop.timedate1.service',
                     install_dir : dbussystemservicedir)
        install_data('org.freedesktop.timedate1.policy',
                     install_dir : polkitpolicydir)
endif
