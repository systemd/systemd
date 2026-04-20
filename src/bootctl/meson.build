# SPDX-License-Identifier: LGPL-2.1-or-later

bootctl_sources = files(
        'bootctl.c',
        'bootctl-install.c',
        'bootctl-link.c',
        'bootctl-random-seed.c',
        'bootctl-reboot-to-firmware.c',
        'bootctl-set-efivar.c',
        'bootctl-status.c',
        'bootctl-uki.c',
        'bootctl-unlink.c',
        'bootctl-cleanup.c',
        'bootctl-util.c',
        'bootspec-util.c',
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
                'dependencies' : [libopenssl],
        },
        test_template + {
                'sources' : files(
                        'test-bootspec-util.c',
                        'bootspec-util.c',
                ),
        },
]
