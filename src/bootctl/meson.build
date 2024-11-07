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

executables += [
        executable_template + {
                'name' : 'bootctl',
                'public' : true,
                'conditions' : [
                          'HAVE_BLKID',
                ],
                'sources' : bootctl_sources,
                'link_with' : boot_link_with,
                'dependencies' : [libblkid, libopenssl],
        },
]
