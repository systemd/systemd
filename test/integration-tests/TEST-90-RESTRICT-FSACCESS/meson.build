# SPDX-License-Identifier: LGPL-2.1-or-later

# Config subtest: no require_signatures — tests error paths and config parsing.
integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'vm' : true,
                'firmware' : 'auto',
                'configuration' : integration_test_template['configuration'] + {
                        'env' : {'TEST_MATCH_SUBTEST' : 'config'},
                },
        },
]

# Enforce subtest: with require_signatures=1 — tests actual BPF enforcement
# via the SecureBoot DB → .platform keyring path (firmware: auto enables
# UEFI/SecureBoot in the test VM).
integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()) + '-enforce',
                'vm' : true,
                'firmware' : 'auto',
                'cmdline' : integration_test_template['cmdline'] + [
                        'dm_verity.require_signatures=1',
                ],
                'configuration' : integration_test_template['configuration'] + {
                        'command' : '/usr/lib/systemd/tests/testdata/units/' + fs.name(meson.current_source_dir()) + '.sh',
                        'env' : {'TEST_MATCH_SUBTEST' : 'enforce'},
                },
        },
]

# dm-verity keyring subtest: exercise the .dm-verity keyring provisioning path
# (kernel commit 033724b1c627, v7.0+) without UEFI/SecureBoot — boots with
# linux-noinitrd so the .platform keyring stays empty and the only way to
# trust the signed verity image is via the dedicated .dm-verity keyring.
integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()) + '-dm-verity-keyring',
                'vm' : true,
                'cmdline' : integration_test_template['cmdline'] + [
                        'dm_verity.require_signatures=1',
                        'dm_verity.keyring_unsealed=1',
                ],
                'configuration' : integration_test_template['configuration'] + {
                        'command' : '/usr/lib/systemd/tests/testdata/units/' + fs.name(meson.current_source_dir()) + '.sh',
                        'env' : {'TEST_MATCH_SUBTEST' : 'dm-verity-keyring'},
                },
        },
]
