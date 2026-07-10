# SPDX-License-Identifier: LGPL-2.1-or-later

executables += [
        libexec_template + {
                'name' : 'systemd-bless-boot',
                'public' : true,
                'conditions' : [
                        'HAVE_BLKID',
                        'ENABLE_BOOTLOADER',
                ],
                'sources' : files('bless-boot.c'),
                'install' : get_option('link-boot-shared') ? 'yes' : 'static',
        },
        generator_template + {
                'name' : 'systemd-bless-boot-generator',
                'conditions' : [
                        'HAVE_BLKID',
                        'ENABLE_BOOTLOADER',
                ],
                'sources' : files('bless-boot-generator.c'),
                'install' : get_option('link-boot-shared') ? 'yes' : 'static',
        },
        libexec_template + {
                'name' : 'systemd-boot-check-no-failures',
                'sources' : files('boot-check-no-failures.c'),
        },
]
