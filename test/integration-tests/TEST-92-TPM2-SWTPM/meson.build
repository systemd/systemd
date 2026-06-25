# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                # The test reboots to verify TPM state persists across boots, so keep storage around.
                'storage' : 'persistent',
                'configuration' : integration_test_template['configuration'] + {
                        'wants' : '@0@ tpm2.target'.format(integration_test_template['configuration']['wants']),
                        'after' : '@0@ tpm2.target'.format(integration_test_template['configuration']['after']),
                },
                'vm' : true,
                # We need to boot in EFI mode (with an initrd) so that an ESP exists for the software TPM to
                # store its state on and so that systemd-tpm2-generator runs in the initrd.
                'firmware' : 'auto',
                # Crucially, do NOT attach a hardware/firmware TPM: that's what makes the generator fall back
                # to the software TPM, which is what this test exercises.
                'tpm' : false,
                'cmdline' : integration_test_template['cmdline'] + [
                        # Opt into the software TPM fallback (off by default).
                        'systemd.tpm2_software_fallback=yes',
                        'systemd.default_device_timeout_sec=300',
                ],
        },
]
