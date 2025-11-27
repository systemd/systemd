# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_dmclone_sources = files(
        'dm-clone-ioctl.c',
        'dmclone.c',
)

executables += [
        executable_template + {
                'name' : 'systemd-dmclone',
                'public' : true,
                'sources' : systemd_dmclone_sources,
        },
]
