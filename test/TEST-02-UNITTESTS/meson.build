# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'coredump-exclude-regex' : '/(bash|python3.[0-9]+|systemd-executor)$',
                'cmdline' : integration_test_template['cmdline'] + [
                        '''

systemd.setenv=TEST_CMDLINE_NEWLINE=foo
                        ''',
                        '''
systemd.setenv=TEST_CMDLINE_NEWLINE=bar
                        ''',
                ],
        },
]
