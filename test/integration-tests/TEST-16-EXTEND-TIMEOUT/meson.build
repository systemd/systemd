# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'configuration' : integration_test_template['configuration'] + {
                        'unit' : integration_test_template['configuration']['unit'] + {
                                'Wants' : ' '.join([
                                        'success-all.service',
                                        'success-start.service',
                                        'success-runtime.service',
                                        'success-stop.service',
                                        'fail-start.service',
                                        'fail-stop.service',
                                        'fail-runtime.service',
                                ]),
                                'StopWhenUnneeded' : 'yes',
                        },
                },
                'coredump-exclude-regex' : '/(bash|sleep)$',
        },
]
