# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
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
        },
        integration_test_template + {
                'name' : 'TEST-70-TPM2-BLS-DTB',
                # The test creates a Type #1 entry and reboots into it, so keep storage around.
                'storage' : 'persistent',
                'configuration' : integration_test_template['configuration'] + {
                        'wants' : '@0@ tpm2.target'.format(integration_test_template['configuration']['wants']),
                        'after' : '@0@ tpm2.target'.format(integration_test_template['configuration']['after']),
                },
                'vm' : true,
                'firmware' : 'uefi',
                'tpm' : true,
                # Keep systemd-boot from treating the VM as safe for automatic Secure Boot key enrollment.
                'qemu-args' : ['-cpu max,hypervisor=off', '-smbios type=0,vm=off'],
                'cmdline' : integration_test_template['cmdline'] + [
                        'systemd.default_device_timeout_sec=300',
                ],
                'priority' : 10,
        },
]
