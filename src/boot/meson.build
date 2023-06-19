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
        boot_link_with = [libsystemd_static, libshared_static]
endif

executables += [
        [
                {
                        'name' : 'bootctl',
                        'public' : true,
                        'conditions' : ['HAVE_BLKID',
                                        'ENABLE_BOOTLOADER'],
                },
                executable_template + {
                        'sources' : bootctl_sources,
                        'link_with' : boot_link_with,
                        'dependencies' : [libblkid,
                                          userspace,
                                          versiondep],
                },
        ],
        [
                {
                        'name' : 'systemd-bless-boot',
                        'public' : true,
                        'conditions' : ['HAVE_BLKID',
                                        'ENABLE_BOOTLOADER'],
                },
                daemon_template + {
                        'sources' : files('bless-boot.c'),
                        'link_with' : boot_link_with,
                        'dependencies' : [libblkid,
                                          userspace,
                                          versiondep],
                },
        ],
        [
                {
                        'name' : 'systemd-bless-boot-generator',
                        'conditions' : ['HAVE_BLKID',
                                        'ENABLE_BOOTLOADER'],
                },
                generator_template + {
                        'sources' : files('bless-boot-generator.c'),
                        'link_with' : boot_link_with,
                },
        ],
        [
                {
                        'name' : 'systemd-measure',
                        'conditions' : ['HAVE_BLKID',
                                        'ENABLE_BOOTLOADER',
                                        'HAVE_OPENSSL',
                                        'HAVE_TPM2'],
                },
                daemon_template + {
                        'sources' : files('measure.c'),
                        'dependencies' : [libopenssl,
                                          userspace,
                                          versiondep],
                },
        ],
        [
                {
                        'name' : 'systemd-pcrphase',
                        'conditions' : ['HAVE_BLKID',
                                        'ENABLE_BOOTLOADER',
                                        'HAVE_OPENSSL',
                                        'HAVE_TPM2'],
                },
                daemon_template + {
                        'sources' : files('pcrphase.c'),
                        'dependencies' : [libblkid,
                                          libopenssl,
                                          tpm2,
                                          userspace,
                                          versiondep],
                },
        ],
        [
                {
                        'name' : 'systemd-boot-check-no-failures',
                },
                daemon_template + {
                        'sources' : files('boot-check-no-failures.c'),
                        'dependencies' : [libblkid,
                                          userspace,
                                          versiondep],
                },
        ],
]
