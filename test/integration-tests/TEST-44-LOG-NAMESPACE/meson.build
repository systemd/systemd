# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'configuration' : integration_test_template['configuration'] + {
                        'unit' : integration_test_template['configuration']['unit'] + {
                                'Wants' : ' '.join([
                                        'systemd-journald@foobar.socket',
                                        'systemd-journald-varlink@foobar.socket',
                                ]),
                                'After' : ' '.join([
                                        'systemd-journald@foobar.socket',
                                        'systemd-journald-varlink@foobar.socket',
                                ]),
                        },
                },
        },
]
