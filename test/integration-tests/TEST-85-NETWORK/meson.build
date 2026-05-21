# SPDX-License-Identifier: LGPL-2.1-or-later

name = fs.name(meson.current_source_dir())

foreach testcase : [
        'NetworkdDHCPServerRelayAgentTests',
]
        integration_tests += [
                integration_test_template + {
                        'name' : '@0@-@1@'.format(name, testcase),
                        'configuration' : integration_test_template['configuration'] + {
                                'command' : '/usr/lib/systemd/tests/testdata/test-network/systemd-networkd-tests.py --no-journal',
                                'env' : integration_test_template['configuration']['env'] + {
                                        'TEST_MATCH_TESTCASE': testcase,
                                }
                        },
                        'priority' : testcase == 'NetworkdDHCPClientTests' ? 10 : 0,
                        'vm' : true,
                },
        ]
endforeach
