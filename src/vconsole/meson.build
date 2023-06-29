# SPDX-License-Identifier: LGPL-2.1-or-later

if conf.get('ENABLE_VCONSOLE') != 1
        subdir_done()
endif

executables += [
        libexec_template + {
                'name' : 'systemd-vconsole-setup',
                'sources' : files('vconsole-setup.c'),
        },
]
