# SPDX-License-Identifier: LGPL-2.1-or-later

# Config subtest: no require_signatures — tests error paths and config parsing.
integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'vm' : true,
                'configuration' : integration_test_template['configuration'] + {
                        'env' : {'TEST_MATCH_SUBTEST' : 'config'},
                },
        },
]

# Enforce subtest: with require_signatures=1 — tests actual BPF enforcement.
integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()) + '-enforce',
                'vm' : true,
                'cmdline' : integration_test_template['cmdline'] + [
                        'dm_verity.require_signatures=1',
                ],
                'configuration' : integration_test_template['configuration'] + {
                        'command' : '/usr/lib/systemd/tests/testdata/units/' + fs.name(meson.current_source_dir()) + '.sh',
                        'env' : {'TEST_MATCH_SUBTEST' : 'enforce'},
                },
        },
]
