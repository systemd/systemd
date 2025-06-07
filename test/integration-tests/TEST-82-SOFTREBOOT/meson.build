# SPDX-License-Identifier: LGPL-2.1-or-later

integration_tests += [
        integration_test_template + {
                'name' : fs.name(meson.current_source_dir()),
                'configuration' : integration_test_template['configuration'] + {
                        'unit' : integration_test_template['configuration']['unit'] + {
                                'DefaultDependencies' : 'no',
                        },
                        'service' : integration_test_template['configuration']['service'] + {
                                'FileDescriptorStoreMax' : '3',
                                'NotifyAccess' : 'all',
                        },
                },
                'cmdline' : ['systemd.set_credential=kernelcmdlinecred:uff'],
                'storage' : 'persistent',
                'vm' : true,
        },
]
