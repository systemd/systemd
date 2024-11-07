# SPDX-License-Identifier: LGPL-2.1-or-later

if get_option('link-boot-shared')
        boot_link_with = [libshared]
else
        boot_link_with = [
                libshared_static,
                libsystemd_static,
        ]
endif

executables += [
        libexec_template + {
                'name' : 'systemd-bless-boot',
                'public' : true,
                'conditions' : [
                        'HAVE_BLKID',
                        'ENABLE_BOOTLOADER',
                ],
                'sources' : files('bless-boot.c'),
                'link_with' : boot_link_with,
                'dependencies' : libblkid,
        },
        generator_template + {
                'name' : 'systemd-bless-boot-generator',
                'conditions' : [
                        'HAVE_BLKID',
                        'ENABLE_BOOTLOADER',
                ],
                'sources' : files('bless-boot-generator.c'),
                'link_with' : boot_link_with,
        },
        libexec_template + {
                'name' : 'systemd-boot-check-no-failures',
                'sources' : files('boot-check-no-failures.c'),
        },
]
