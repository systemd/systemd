# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'cmdline' : integration_test_template['cmdline'] + [
                        'apparmor=0',
                        'selinux=1',
                        'enforcing=0',
                        'lsm=selinux',
                        'systemd.wants=autorelabel.service',
                        'systemd.wants=firstboot-autorelabel.service',
                ],
                # FIXME; Figure out why reboot sometimes hangs with 'linux' firmware.
                'firmware' : 'uefi',
        },
]
