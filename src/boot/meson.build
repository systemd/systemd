# SPDX-License-Identifier: LGPL-2.1-or-later

bootctl_sources = files(
        'bootctl-install.c',
        'bootctl-random-seed.c',
        'bootctl-reboot-to-firmware.c',
        'bootctl-set-efivar.c',
        'bootctl-status.c',
        'bootctl-systemd-efi-options.c',
        'bootctl-uki.c',
        'bootctl-util.c',
        'bootctl.c',
)

if get_option('link-boot-shared')
        boot_link_with = [libshared]
else
        boot_link_with = [
                libshared_static,
                libsystemd_static,
        ]
endif

executables += [
        executable_template + {
                'name' : 'bootctl',
                'public' : true,
                'conditions' : [
                          'HAVE_BLKID',
                ],
                'sources' : bootctl_sources,
                'link_with' : boot_link_with,
                'dependencies' : libblkid,
        },
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
                'name' : 'systemd-measure',
                'conditions' : [
                        'HAVE_BLKID',
                        'HAVE_OPENSSL',
                        'HAVE_TPM2',
                ],
                'sources' : files('measure.c'),
                'dependencies' : libopenssl,
        },
        libexec_template + {
                'name' : 'systemd-boot-check-no-failures',
                'sources' : files('boot-check-no-failures.c'),
        },
]
