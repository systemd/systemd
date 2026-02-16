# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_clone_sources = files(
        'clone-ioctl.c',
        'clone.c',
)

executables += [
        executable_template + {
                'name' : 'systemd-clone',
                'public' : true,
                'sources' : systemd_clone_sources,
        },
        generator_template + {
                'name' : 'systemd-clone-generator',
                'sources' : files('clone-generator.c'),
        },
]
