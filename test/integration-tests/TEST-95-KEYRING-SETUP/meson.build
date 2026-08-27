# SPDX-License-Identifier: LGPL-2.1-or-later

# Without dm_verity.keyring_unsealed=1 the kernel seals .dm-verity empty and the
# service must leave it alone; .fs-verity is provisioned at runtime.
integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'vm' : true,
                'configuration' : integration_test_template['configuration'] + {
                        'env' : {'TEST_MATCH_SUBTEST' : '[.](sealed|fs-verity)[.]sh$'},
                },
        },
]

# With the flag the service provisions .dm-verity from the VOA hierarchy at
# boot, and the kernel verifies the signed test image against it.
integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()) + '-unsealed',
                'vm' : true,
                'cmdline' : integration_test_template['cmdline'] + [
                        'dm_verity.keyring_unsealed=1',
                        'dm_verity.require_signatures=1',
                ],
                'configuration' : integration_test_template['configuration'] + {
                        'command' : '/usr/lib/systemd/tests/testdata/units/' + fs.name(meson.current_source_dir()) + '.sh',
                        'env' : {'TEST_MATCH_SUBTEST' : 'unsealed'},
                },
        },
]
