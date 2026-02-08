# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'vm' : true,
                'configuration' : integration_test_template['configuration'] + {
                        'command' : '/usr/lib/systemd/tests/testdata/test-devlinkd/systemd-devlinkd-tests.py',
                },
        },
]
