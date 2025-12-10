# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_clonesetup_sources = files(
        'clonesetup-ioctl.c',
        'clonesetup.c',
)

executables += [
        libexec_template + {
                'name' : 'systemd-clonesetup',
                'sources' : systemd_clonesetup_sources,
        },
        generator_template + {
                'name' : 'systemd-clonesetup-generator',
                'sources' : files('clonesetup-generator.c'),
        },
]
