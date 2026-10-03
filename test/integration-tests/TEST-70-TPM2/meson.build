# SPDX-License-Identifier: LGPL-2.1-or-later

name = fs.name(meson.current_source_dir())

tpm2_test_template = integration_test_template + {
        'configuration' : integration_test_template['configuration'] + {
                'wants' : '@0@ tpm2.target'.format(integration_test_template['configuration']['wants']),
                'after' : '@0@ tpm2.target'.format(integration_test_template['configuration']['after']),
        },
        'vm' : true,
        'firmware' : 'auto',
        'tpm' : true,
        'cmdline' : integration_test_template['cmdline'] + [
                'systemd.default_device_timeout_sec=300',
        ],
}

integration_tests += [
        tpm2_test_template + {
                'name' : name,
        },
        tpm2_test_template + {
                'name' : '@0@-BLS-DTB'.format(name),
                # The test creates a Type #1 entry and reboots into it, so keep storage around.
                'storage' : 'persistent',
                'firmware' : 'uefi',
                # Prevent systemd-boot from treating the VM as safe for automatic Secure Boot key enrollment.
                'hide-hypervisor' : true,
                'priority' : 10,
        },
]
