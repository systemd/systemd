# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'unit' : files('TEST-69-SHUTDOWN.service'),
                'configuration' : integration_test_template['configuration'] + {
                        'wants' : '@0@ systemd-user-sessions.service'.format(integration_test_template['configuration']['wants']),
                        'after' : '@0@ systemd-user-sessions.service'.format(integration_test_template['configuration']['after']),
                },
        },
]
