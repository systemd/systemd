# SPDX-License-Identifier: LGPL-2.1-or-later

name = fs.name(meson.current_source_dir())
unit = configure_file(
        input : files('../test.service.in'),
        output : '@0@.service'.format(name),
        configuration : integration_test_template['configuration'] + {
                'command' : '@0@ --no-journal'.format(testdata_dir / 'test-network/systemd-networkd-tests.py')
        },
)

foreach testcase : [
        'NetworkctlTests',
        'NetworkdMatchTests',
        'WaitOnlineTests',
        'NetworkdNetDevTests',
        'NetworkdL2TPTests',
        'NetworkdNetworkTests',
        'NetworkdTCTests',
        'NetworkdStateFileTests',
        'NetworkdBondTests',
        'NetworkdBridgeTests',
        'NetworkdSRIOVTests',
        'NetworkdLLDPTests',
        'NetworkdRATests',
        'NetworkdDHCPServerTests',
        'NetworkdDHCPServerRelayAgentTests',
        'NetworkdDHCPClientTests',
        'NetworkdDHCPPDTests',
        'NetworkdIPv6PrefixTests',
        'NetworkdMTUTests',
]
        integration_tests += [
                integration_test_template + {
                        'name' : '@0@-@1@'.format(name, testcase),
                        'unit' : unit,
                        'cmdline' : integration_test_template['cmdline'] + [
                                'systemd.setenv=TEST_MATCH_TESTCASE=@0@'.format(testcase)
                        ],
                },
        ]
endforeach
