# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'configuration' : integration_test_template['configuration'] + {
                        'type' : 'notify',
                        'service' : integration_test_template['configuration']['service'] + {
                                'NotifyAccess' : 'all',
                        },
                },
        },
]
