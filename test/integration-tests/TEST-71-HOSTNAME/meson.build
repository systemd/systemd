# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'configuration' : integration_test_template['configuration'] + {
                        # Do not request user session, as it may trigger to start
                        # hostnamed in an unexpected timing, and the test may fail.
                        'wants' : 'multi-user.target',
                        'after' : 'multi-user.target',
                },
        },
]
