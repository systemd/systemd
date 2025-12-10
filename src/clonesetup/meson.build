# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_clonesetup_sources = files(
        'clonesetup-ioctl.c',
        'clonesetup.c',
)

executables += [
        executable_template + {
                'name' : 'systemd-clonesetup',
                'public' : true,
                'sources' : systemd_clonesetup_sources,
        },
        generator_template + {
                'name' : 'systemd-clonesetup-generator',
                'sources' : files('clonesetup-generator.c'),
        },
]
