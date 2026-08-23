# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : 'TEST-91-LIVEUPDATE',
                'configuration' : integration_test_template['configuration'] + {
                        'unit' : integration_test_template['configuration']['unit'] + {
                                'DefaultDependencies' : 'no',
                        },
                        'service' : integration_test_template['configuration']['service'] + {
                                'FileDescriptorStoreMax' : '20',
                                'FileDescriptorStorePreserve' : 'yes',
                                'NotifyAccess' : 'all',
                        },
                },
                'cmdline' : ['kho=on', 'liveupdate=on', 'systemd.minimum_uptime_sec=0'],
                'storage' : 'persistent',
                'vm' : true,
                'firmware' : 'uefi',
        },
]
